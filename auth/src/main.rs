// kaguya-auth: auth/ReBAC service for a Dex-fronted Lore server.
//
// Lore expects a UCS-style auth service for two things this fills:
//   - token exchange: the client presents its Dex identity token here and
//     receives a repository-scoped "multiresource" token loreserver accepts, and
//   - the ReBAC gRPC API loreserver calls to create/authorize resources
//     (RebacApi + UrcAuthApi.CheckUserPermission / LookupUserPermissions).
//
// Authorization is real (not all-allow): a SQLite-backed store (see `store`)
// records who owns / may access which repository. `CreateResource` records the
// creator as owner; the exchange mints a token whose `resources` claim is scoped
// to exactly what the caller is allowed (with per-role permissions), which is
// what loreserver's storage/revision authorization reads. Grants and groups are
// managed with the binary's admin subcommands (see `run_admin`).
//
// Identity still comes from Dex: the exchange verifies the caller's Dex token
// (see `verify`) before minting, and the minted token is signed with our own key
// (see `keys`), which loreserver trusts via `[server.auth]` + the published JWKS.
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;

use tonic::{transport::Server, Request, Response, Status};

mod jwks;
mod keys;
mod store;
mod verify;

use keys::{ResourceGrant, Signer};
use store::{Role, Store};
use verify::{DexVerifier, Identity, SelfVerifier};

pub mod ucs_auth {
    include!(concat!(env!("OUT_DIR"), "/ucs.auth.rs"));
}
pub mod epic_urc {
    include!(concat!(env!("OUT_DIR"), "/epic_urc.rs"));
}

use epic_urc::urc_auth_api_server::{UrcAuthApi, UrcAuthApiServer};
use epic_urc::*;
use ucs_auth::rebac_api_server::{RebacApi, RebacApiServer};
use ucs_auth::{
    CreateResourceRequest, CreateResourceResponse, DeleteResourceRequest, DeleteResourceResponse,
};

type BoxError = Box<dyn Error + Send + Sync>;

// A proto ResourcePermission carrying a role's permission strings.
fn grant(resource_id: String, role: Role) -> ResourcePermission {
    ResourcePermission {
        resource_id,
        permission: role.permissions(),
    }
}

// Pull the bearer token out of the request's authorization metadata.
fn bearer<T>(req: &Request<T>) -> String {
    req.metadata()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .unwrap_or("")
        .to_string()
}

struct Rebac {
    store: Arc<Store>,
    identity: Arc<Identity>,
}

#[tonic::async_trait]
impl RebacApi for Rebac {
    async fn create_resource(
        &self,
        req: Request<CreateResourceRequest>,
    ) -> Result<Response<CreateResourceResponse>, Status> {
        let sub = self.identity.subject(&bearer(&req)).await.map_err(|e| {
            eprintln!("create_resource: rejecting token: {e}");
            Status::unauthenticated("invalid token")
        })?;
        let r = req.into_inner();
        self.store
            .record_owner(&sub, &r.resource_id, &r.resource_name)
            .map_err(|e| {
                eprintln!("create_resource: store error: {e}");
                Status::internal("store error")
            })?;
        Ok(Response::new(CreateResourceResponse {}))
    }

    async fn delete_resource(
        &self,
        req: Request<DeleteResourceRequest>,
    ) -> Result<Response<DeleteResourceResponse>, Status> {
        let sub = self.identity.subject(&bearer(&req)).await.map_err(|e| {
            eprintln!("delete_resource: rejecting token: {e}");
            Status::unauthenticated("invalid token")
        })?;
        let r = req.into_inner();
        // Only an owner may delete the resource.
        if self.store.role_for(&sub, &r.resource_id) != Some(Role::Owner) {
            return Err(Status::permission_denied("not an owner of this resource"));
        }
        self.store.delete_resource(&r.resource_id).map_err(|e| {
            eprintln!("delete_resource: store error: {e}");
            Status::internal("store error")
        })?;
        Ok(Response::new(DeleteResourceResponse {}))
    }
}

struct Auth {
    signer: Arc<Signer>,
    dex: Arc<DexVerifier>,
    store: Arc<Store>,
    identity: Arc<Identity>,
    /// `iss` stamped on minted tokens; must equal loreserver's `jwt_issuer`.
    auth_issuer: String,
    /// `aud` stamped on minted tokens; must be in loreserver's `jwt_audience`.
    audience: String,
}

#[tonic::async_trait]
impl UrcAuthApi for Auth {
    async fn health_check(
        &self,
        _req: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: "ok".into(),
        }))
    }

    async fn check_user_permission(
        &self,
        req: Request<CheckUserPermissionRequest>,
    ) -> Result<Response<CheckUserPermissionResponse>, Status> {
        let sub = self.identity.subject(&bearer(&req)).await.map_err(|e| {
            eprintln!("check_user_permission: rejecting token: {e}");
            Status::unauthenticated("invalid token")
        })?;
        let ids = req.into_inner().resource_id;
        let mut allowed = Vec::new();
        let mut denied = Vec::new();
        for id in ids {
            match self.store.role_for(&sub, &id) {
                Some(role) => allowed.push(grant(id, role)),
                None => denied.push(ResourcePermission {
                    resource_id: id,
                    permission: vec![],
                }),
            }
        }
        Ok(Response::new(CheckUserPermissionResponse {
            allowed_resource_permission: allowed,
            denied_resource_permission: denied,
        }))
    }

    async fn lookup_user_permissions(
        &self,
        req: Request<LookupUserPermissionsRequest>,
    ) -> Result<Response<LookupUserPermissionsResponse>, Status> {
        let sub = self.identity.subject(&bearer(&req)).await.map_err(|e| {
            eprintln!("lookup_user_permissions: rejecting token: {e}");
            Status::unauthenticated("invalid token")
        })?;
        // resource_filter is "urc"; every repository resource matches it, so we
        // return all the caller can reach (single page — loreserver does not page).
        let _ = req.into_inner();
        let resource_permission = self
            .store
            .accessible(&sub)
            .into_iter()
            .map(|id| {
                let role = self.store.role_for(&sub, &id).unwrap_or(Role::Member);
                grant(id, role)
            })
            .collect();
        Ok(Response::new(LookupUserPermissionsResponse {
            resource_permission,
            next_page_token: None,
        }))
    }

    async fn get_user_info(
        &self,
        _req: Request<GetUserInfoRequest>,
    ) -> Result<Response<GetUserInfoResponse>, Status> {
        Ok(Response::new(GetUserInfoResponse { user_info: vec![] }))
    }

    async fn start_auth_session(
        &self,
        _req: Request<StartAuthSessionRequest>,
    ) -> Result<Response<StartAuthSessionResponse>, Status> {
        Err(Status::unimplemented("start_auth_session"))
    }
    async fn get_auth_session(
        &self,
        _req: Request<GetAuthSessionRequest>,
    ) -> Result<Response<GetAuthSessionResponse>, Status> {
        Err(Status::unimplemented("get_auth_session"))
    }
    async fn refresh_auth_session(
        &self,
        _req: Request<RefreshAuthSessionRequest>,
    ) -> Result<Response<RefreshAuthSessionResponse>, Status> {
        Err(Status::unimplemented("refresh_auth_session"))
    }
    async fn verify_user(
        &self,
        _req: Request<VerifyUserRequest>,
    ) -> Result<Response<VerifyUserResponse>, Status> {
        Err(Status::unimplemented("verify_user"))
    }
    async fn exchange_external_token_for_user_token(
        &self,
        _req: Request<ExchangeExternalTokenForUserTokenRequest>,
    ) -> Result<Response<ExchangeExternalTokenForUserTokenResponse>, Status> {
        Err(Status::unimplemented(
            "exchange_external_token_for_user_token",
        ))
    }
    async fn exchange_api_key_for_user_token(
        &self,
        _req: Request<ExchangeApiKeyForUserTokenRequest>,
    ) -> Result<Response<ExchangeApiKeyForUserTokenResponse>, Status> {
        Err(Status::unimplemented("exchange_api_key_for_user_token"))
    }

    /// Verify the caller's Dex token, then mint a Lore token scoped to the
    /// repositories the caller is actually allowed. Requested resources the
    /// caller has no grant on are dropped, so loreserver's storage/revision
    /// authorization (which reads the `resources` claim) denies them.
    async fn exchange_user_token_for_multiresource_token(
        &self,
        req: Request<ExchangeUserTokenForMultiresourceTokenRequest>,
    ) -> Result<Response<ExchangeUserTokenForMultiresourceTokenResponse>, Status> {
        let token = bearer(&req);
        if token.is_empty() {
            return Err(Status::unauthenticated("missing bearer token"));
        }

        let claims = self.dex.verify(&token).await.map_err(|e| {
            eprintln!("exchange: rejecting identity token: {e}");
            Status::unauthenticated("invalid identity token")
        })?;

        let requested = req.into_inner().resource_id;
        let resources: Vec<ResourceGrant> = requested
            .into_iter()
            .filter_map(|id| {
                self.store.role_for(&claims.sub, &id).map(|role| ResourceGrant {
                    resource_id: id,
                    permission: role.permissions(),
                })
            })
            .collect();

        // Display fields carried from the verified Dex identity; the lore CLI
        // requires `name` when it decodes the exchanged token.
        let name = claims
            .name
            .clone()
            .or_else(|| claims.preferred_username.clone())
            .or_else(|| claims.email.clone())
            .unwrap_or_else(|| claims.sub.clone());
        let preferred_username = claims
            .preferred_username
            .clone()
            .or_else(|| claims.email.clone())
            .unwrap_or_else(|| name.clone());

        let minted = self
            .signer
            .mint(
                &self.auth_issuer,
                &self.audience,
                &claims.sub,
                &name,
                &preferred_username,
                claims.exp,
                resources,
            )
            .map_err(|e| {
                eprintln!("exchange: minting token failed: {e}");
                Status::internal("token issuance failed")
            })?;

        Ok(Response::new(
            ExchangeUserTokenForMultiresourceTokenResponse {
                token: Some(UserToken {
                    user_token: minted,
                    expires_at: claims.exp as i64,
                    user_id: claims.sub,
                    user_name: name,
                }),
            },
        ))
    }

    async fn get_user_id(
        &self,
        _req: Request<GetUserIdRequest>,
    ) -> Result<Response<GetUserIdResponse>, Status> {
        Err(Status::unimplemented("get_user_id"))
    }
    async fn get_provider_user_id(
        &self,
        _req: Request<GetProviderUserIdRequest>,
    ) -> Result<Response<GetProviderUserIdResponse>, Status> {
        Err(Status::unimplemented("get_provider_user_id"))
    }
}

fn env_required(key: &str) -> Result<String, BoxError> {
    std::env::var(key).map_err(|_| format!("missing required env var {key}").into())
}

fn db_path() -> String {
    std::env::var("KAGUYA_DB_PATH").unwrap_or_else(|_| "/data/rebac.db".into())
}

const ADMIN_USAGE: &str = "\
usage: kaguya-auth <command>
  grant <subject> <urc-id> <owner|member>   grant a role on a resource
  revoke <subject> <urc-id>                  remove a grant
  group-add <group> <subject>                add a subject to a group
  group-del <group> <subject>                remove a subject from a group
  ls <urc-id>                                list grants on a resource
subjects are user ids (JWT sub) or 'group:<name>'. Run with no command to serve.";

// Admin CLI: manage grants/groups directly against the ReBAC store. Runs when
// the binary is invoked with arguments (e.g. `docker compose exec auth
// kaguya-auth grant <sub> <urc-id> owner`), then exits without starting the
// server.
fn run_admin(args: &[String]) -> Result<(), BoxError> {
    let store = Store::open(&db_path())?;
    let rest: Vec<&str> = args[1..].iter().map(String::as_str).collect();
    match (args[0].as_str(), rest.as_slice()) {
        ("grant", [subject, urc, role]) => {
            let role = Role::parse(role).ok_or("role must be 'owner' or 'member'")?;
            store.grant(subject, urc, role)?;
            println!("granted {} on {urc} to {subject}", role.as_str());
        }
        ("revoke", [subject, urc]) => {
            let n = store.revoke(subject, urc)?;
            println!("removed {n} grant(s) for {subject} on {urc}");
        }
        ("group-add", [group, subject]) => {
            store.add_group_member(group, subject)?;
            println!("added {subject} to group {group}");
        }
        ("group-del", [group, subject]) => {
            let n = store.remove_group_member(group, subject)?;
            println!("removed {n} membership(s) of {subject} in group {group}");
        }
        ("ls", [urc]) => {
            for (subject, role) in store.list_grants(urc) {
                println!("{role}\t{subject}");
            }
        }
        _ => {
            eprintln!("{ADMIN_USAGE}");
            return Err("invalid admin command".into());
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !args.is_empty() {
        return run_admin(&args);
    }

    let dex_issuer = env_required("KAGUYA_DEX_ISSUER")?;
    let audience = env_required("KAGUYA_JWT_AUDIENCE")?;
    let auth_issuer = env_required("KAGUYA_AUTH_ISSUER")?;
    let keys_dir = PathBuf::from(std::env::var("KAGUYA_KEYS_DIR").unwrap_or_else(|_| "/keys".into()));

    let signer = Arc::new(Signer::load_or_generate(&keys_dir)?);

    // Publish the combined JWKS (our signing key + Dex's keys) before serving, so
    // loreserver's eager startup fetch and the container healthcheck find it. A
    // background refresh tracks Dex key rotation and recovers if Dex was down.
    let http = reqwest::Client::new();
    jwks::publish(&keys_dir, &http, &dex_issuer, signer.own_jwk()).await?;
    jwks::spawn_refresh(
        keys_dir.clone(),
        http,
        dex_issuer.clone(),
        signer.own_jwk().clone(),
        std::time::Duration::from_secs(300),
    );

    let store = Arc::new(Store::open(&db_path())?);
    let dex = Arc::new(DexVerifier::new(dex_issuer.clone(), audience.clone()));
    let identity = Arc::new(Identity {
        self_verifier: SelfVerifier::new(signer.own_jwk(), auth_issuer.clone(), audience.clone())?,
        dex: dex.clone(),
    });

    let rebac = Rebac {
        store: store.clone(),
        identity: identity.clone(),
    };
    let auth = Auth {
        signer: signer.clone(),
        dex,
        store,
        identity,
        auth_issuer: auth_issuer.clone(),
        audience: audience.clone(),
    };

    let addr = "0.0.0.0:8080".parse()?;
    println!(
        "kaguya-auth listening on {addr}; issuer={auth_issuer}, audience={audience}, \
         verifying Dex tokens from {dex_issuer}, db={}, kid={}",
        db_path(),
        signer.kid
    );
    Server::builder()
        .add_service(RebacApiServer::new(rebac))
        .add_service(UrcAuthApiServer::new(auth))
        .serve(addr)
        .await?;
    Ok(())
}
