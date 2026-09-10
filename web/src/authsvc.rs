//! gRPC client to kaguya-auth (internal). Turns the user's Dex identity into a
//! Lore token, and (later) mints per-repository authorization tokens.
use tonic::transport::Channel;
use tonic::Request;

use crate::pb::epic_urc::urc_auth_api_client::UrcAuthApiClient;
use crate::pb::epic_urc::{
    ExchangeExternalTokenForUserTokenRequest, ExchangeUserTokenForMultiresourceTokenRequest,
};

pub struct AuthClient {
    endpoint: String,
}

/// The identity + token returned from an exchange, for the session.
pub struct Issued {
    pub token: String,
    pub user_id: String,
    pub user_name: String,
    pub expires_at: i64,
}

impl AuthClient {
    pub fn new(endpoint: String) -> Self {
        AuthClient { endpoint }
    }

    async fn connect(&self) -> Result<UrcAuthApiClient<Channel>, String> {
        UrcAuthApiClient::connect(self.endpoint.clone())
            .await
            .map_err(|e| format!("auth connect: {e}"))
    }

    /// Exchange a Dex identity token for our own signed UCS authn token (the
    /// user's Lore identity for the rest of the session).
    pub async fn exchange_external(&self, dex_token: &str) -> Result<Issued, String> {
        let mut client = self.connect().await?;
        let resp = client
            .exchange_external_token_for_user_token(ExchangeExternalTokenForUserTokenRequest {
                external_token: dex_token.to_string(),
                token_type: "external".to_string(),
            })
            .await
            .map_err(|e| format!("exchange_external: {e}"))?;
        let t = resp
            .into_inner()
            .user_token
            .filter(|t| !t.user_token.is_empty())
            .ok_or_else(|| "auth service returned no user token".to_string())?;
        Ok(Issued {
            token: t.user_token,
            user_id: t.user_id,
            user_name: t.user_name,
            expires_at: t.expires_at,
        })
    }

    /// Exchange the user's authn token for a token scoped to `resource_id`
    /// (`urc-{repo}`), for repo-scoped reads (branches/history/tree/content).
    #[allow(dead_code)] // used by repo-scoped browsing (next increment)
    pub async fn exchange_resource(
        &self,
        authn_token: &str,
        resource_id: &str,
    ) -> Result<String, String> {
        let mut client = self.connect().await?;
        let mut req = Request::new(ExchangeUserTokenForMultiresourceTokenRequest {
            resource_id: vec![resource_id.to_string()],
        });
        bearer(&mut req, authn_token)?;
        let resp = client
            .exchange_user_token_for_multiresource_token(req)
            .await
            .map_err(|e| format!("exchange_resource: {e}"))?;
        resp.into_inner()
            .token
            .map(|t| t.user_token)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| "auth service returned no scoped token".to_string())
    }
}

#[allow(dead_code)] // used by exchange_resource (next increment)
fn bearer<T>(req: &mut Request<T>, token: &str) -> Result<(), String> {
    let value = format!("Bearer {token}")
        .parse()
        .map_err(|_| "invalid bearer token".to_string())?;
    req.metadata_mut().insert("authorization", value);
    Ok(())
}
