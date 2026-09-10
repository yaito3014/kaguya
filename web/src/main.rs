//! kaguya-web: a read-only web frontend (BFF) for the self-hosted Lore server.
//!
//! The browser talks only to this service. It logs the user in via Dex
//! (auth-code + PKCE), exchanges that identity through kaguya-auth for a Lore
//! token (see `authsvc`), keeps it in a server-side session, and reads
//! repositories from loreserver over gRPC (see `lore`) on the user's behalf — so
//! per-user ReBAC is enforced. A small SPA (served from `static/`) calls the
//! JSON API under `/api`.
mod authsvc;
mod lore;
mod oidc;
mod pb;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use axum::extract::Query;
use axum::extract::State;
use axum::http::header;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::Json;
use axum::Router;
use serde::Deserialize;
use tower_http::services::ServeDir;

use authsvc::AuthClient;
use lore::LoreClient;
use oidc::Oidc;

const COOKIE: &str = "kw_session";
const PENDING_TTL: i64 = 600; // seconds a login may stay in flight

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

struct Session {
    token: String,
    user_name: String,
    sub: String,
    expires_at: i64,
}

struct Pending {
    verifier: String,
    expires_at: i64,
}

#[derive(Default)]
struct Store {
    sessions: Mutex<HashMap<String, Session>>,
    pending: Mutex<HashMap<String, Pending>>,
}

impl Store {
    fn start_login(&self, state: String, verifier: String) {
        let mut m = self.pending.lock().unwrap();
        m.retain(|_, p| p.expires_at > now());
        m.insert(
            state,
            Pending {
                verifier,
                expires_at: now() + PENDING_TTL,
            },
        );
    }

    fn take_pending(&self, state: &str) -> Option<String> {
        let mut m = self.pending.lock().unwrap();
        m.remove(state)
            .filter(|p| p.expires_at > now())
            .map(|p| p.verifier)
    }

    fn create(&self, id: String, session: Session) {
        let mut m = self.sessions.lock().unwrap();
        m.retain(|_, s| s.expires_at > now());
        m.insert(id, session);
    }

    /// Returns `(token, user_name, sub)` for a live session.
    fn get(&self, id: &str) -> Option<(String, String, String)> {
        let m = self.sessions.lock().unwrap();
        m.get(id)
            .filter(|s| s.expires_at > now())
            .map(|s| (s.token.clone(), s.user_name.clone(), s.sub.clone()))
    }

    fn remove(&self, id: &str) {
        self.sessions.lock().unwrap().remove(id);
    }
}

struct App {
    oidc: Oidc,
    auth: AuthClient,
    lore: LoreClient,
    store: Store,
}

// --- cookie / session helpers -------------------------------------------------

fn session_id(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    let prefix = format!("{COOKIE}=");
    cookie
        .split(';')
        .map(str::trim)
        .find_map(|kv| kv.strip_prefix(&prefix).map(String::from))
}

fn session(app: &App, headers: &HeaderMap) -> Option<(String, String, String)> {
    session_id(headers).and_then(|id| app.store.get(&id))
}

fn session_cookie(id: &str, max_age: i64) -> String {
    format!("{COOKIE}={id}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={max_age}")
}

fn clear_cookie() -> String {
    format!("{COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
}

fn redirect(location: &str, set_cookie: Option<&str>) -> Response {
    let mut builder = axum::http::Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location);
    if let Some(c) = set_cookie {
        builder = builder.header(header::SET_COOKIE, c);
    }
    builder
        .body(axum::body::Body::empty())
        .expect("valid redirect response")
}

// --- handlers -----------------------------------------------------------------

async fn login(State(app): State<Arc<App>>) -> Response {
    let state = oidc::random_state();
    let verifier = oidc::code_verifier();
    let challenge = oidc::code_challenge(&verifier);
    app.store.start_login(state.clone(), verifier);
    match app.oidc.authorize_url(&state, &challenge).await {
        Ok(url) => redirect(&url, None),
        Err(e) => {
            eprintln!("login: {e}");
            (StatusCode::BAD_GATEWAY, "login unavailable").into_response()
        }
    }
}

#[derive(Deserialize)]
struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn callback(State(app): State<Arc<App>>, Query(q): Query<Callback>) -> Response {
    if let Some(err) = q.error {
        eprintln!("callback: Dex returned error: {err}");
        return redirect("/?login=failed", None);
    }
    let (Some(code), Some(state)) = (q.code, q.state) else {
        return redirect("/?login=failed", None);
    };
    let Some(verifier) = app.store.take_pending(&state) else {
        eprintln!("callback: unknown or expired state");
        return redirect("/?login=failed", None);
    };
    let id_token = match app.oidc.exchange_code(&code, &verifier).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("callback: exchange_code: {e}");
            return redirect("/?login=failed", None);
        }
    };
    let issued = match app.auth.exchange_external(&id_token).await {
        Ok(i) => i,
        Err(e) => {
            eprintln!("callback: exchange_external: {e}");
            return redirect("/?login=failed", None);
        }
    };
    let exp = if issued.expires_at > now() {
        issued.expires_at
    } else {
        now() + 3600
    };
    let sid = oidc::random_state();
    app.store.create(
        sid.clone(),
        Session {
            token: issued.token,
            user_name: issued.user_name,
            sub: issued.user_id,
            expires_at: exp,
        },
    );
    redirect("/", Some(&session_cookie(&sid, (exp - now()).max(0))))
}

async fn logout(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    if let Some(id) = session_id(&headers) {
        app.store.remove(&id);
    }
    redirect("/", Some(&clear_cookie()))
}

async fn me(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    match session(&app, &headers) {
        Some((_, user_name, sub)) => {
            Json(serde_json::json!({ "user_name": user_name, "sub": sub })).into_response()
        }
        None => (StatusCode::UNAUTHORIZED, "not logged in").into_response(),
    }
}

async fn repos(State(app): State<Arc<App>>, headers: HeaderMap) -> Response {
    let Some((token, _, _)) = session(&app, &headers) else {
        return (StatusCode::UNAUTHORIZED, "not logged in").into_response();
    };
    match app.lore.list_repos(&token).await {
        Ok(list) => Json(list).into_response(),
        Err(e) => {
            eprintln!("repos: {e}");
            (StatusCode::BAD_GATEWAY, "could not list repositories").into_response()
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_req(key: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    std::env::var(key).map_err(|_| format!("missing required env var {key}").into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let issuer = env_or("KAGUYA_WEB_DEX_ISSUER", "https://dex.yai.to/dex");
    let client_id = env_req("KAGUYA_WEB_CLIENT_ID")?;
    let redirect_uri = env_req("KAGUYA_WEB_REDIRECT_URI")?;
    let auth_grpc = env_or("KAGUYA_WEB_AUTH_GRPC", "http://auth:8080");
    let lore_grpc = env_or("KAGUYA_WEB_LORE_GRPC", "http://lore:41337");
    let static_dir = env_or("KAGUYA_WEB_STATIC_DIR", "static");
    let listen = env_or("KAGUYA_WEB_LISTEN", "0.0.0.0:8090");

    let app = Arc::new(App {
        oidc: Oidc::new(issuer.clone(), client_id.clone(), redirect_uri),
        auth: AuthClient::new(auth_grpc),
        lore: LoreClient::new(lore_grpc),
        store: Store::default(),
    });

    let router = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", get(logout))
        .route("/api/me", get(me))
        .route("/api/repos", get(repos))
        .fallback_service(ServeDir::new(static_dir))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    println!("kaguya-web listening on {listen}; client_id={client_id}, issuer={issuer}");
    axum::serve(listener, router).await?;
    Ok(())
}
