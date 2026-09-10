//! Dex OIDC: authorization-code flow with PKCE. The frontend is a public client
//! (no secret), so every login generates a PKCE verifier; the code challenge
//! binds the callback's code to this login.
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;

#[derive(Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

pub struct Oidc {
    issuer: String,
    client_id: String,
    redirect_uri: String,
    client: reqwest::Client,
}

impl Oidc {
    pub fn new(issuer: String, client_id: String, redirect_uri: String) -> Self {
        Oidc {
            issuer,
            client_id,
            redirect_uri,
            client: reqwest::Client::new(),
        }
    }

    async fn discovery(&self) -> Result<Discovery, String> {
        // Trim a trailing slash so an issuer like ".../o/lore/" does not yield a
        // double-slashed (404) well-known URL.
        let url = format!(
            "{}/.well-known/openid-configuration",
            self.issuer.trim_end_matches('/')
        );
        self.client
            .get(&url)
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("discovery {url}: {e}"))?
            .json()
            .await
            .map_err(|e| format!("discovery parse: {e}"))
    }

    /// The URL to redirect the browser to for login.
    pub async fn authorize_url(&self, state: &str, code_challenge: &str) -> Result<String, String> {
        let disco = self.discovery().await?;
        let mut url = reqwest::Url::parse(&disco.authorization_endpoint)
            .map_err(|e| format!("authorize url: {e}"))?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("scope", "openid profile email")
            .append_pair("state", state)
            .append_pair("code_challenge", code_challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url.to_string())
    }

    /// Exchange the callback's authorization code for the Dex id_token.
    pub async fn exchange_code(&self, code: &str, code_verifier: &str) -> Result<String, String> {
        let disco = self.discovery().await?;
        let resp: TokenResponse = self
            .client
            .post(&disco.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("client_id", self.client_id.as_str()),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("token exchange: {e}"))?
            .json()
            .await
            .map_err(|e| format!("token parse: {e}"))?;
        Ok(resp.id_token)
    }
}

/// A fresh PKCE code verifier (RFC 7636): 32 random bytes, base64url.
pub fn code_verifier() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The S256 code challenge for a verifier.
pub fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// An unguessable opaque `state` value.
pub fn random_state() -> String {
    format!("{:032x}", rand::random::<u128>())
}
