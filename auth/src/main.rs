// kaguya-auth: auth/ReBAC service for a Dex-fronted Lore server.
//
// Lore expects a UCS-style auth service for two things this fills:
//   - the ReBAC gRPC API loreserver calls to create/authorize resources
//     (RebacApi + UrcAuthApi.CheckUserPermission / LookupUserPermissions), and
//   - token exchange: the client presents its Dex identity token here and
//     receives a "multiresource" token that loreserver's storage/revision
//     authorization accepts.
//
// The exchange is the load-bearing part. loreserver's `verify_authorization`
// requires the presented token to carry a `resources` claim naming the
// repository (`urc-{id}`); a plain Dex token has none. So we verify the Dex
// token (signature/issuer/audience/expiry, see `verify`) and then MINT a fresh
// RS256 token that carries the requested resource grants, signed with our own
// key (see `keys`). loreserver trusts us as the issuer of exchanged tokens via
// `[server.auth].jwt_issuer` + `[server.auth.jwk].endpoint = file://` pointing at
// the JWKS we publish to the shared volume.
//
// The ReBAC methods still grant every action to any caller; real per-repository
// policy can be added there later. Authentication is enforced both by our Dex
// verification above and by loreserver's own JWT check.
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;

use tonic::{transport::Server, Request, Response, Status};

mod jwks;
mod keys;
mod verify;

use keys::Signer;
use verify::DexVerifier;

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

// A proto ResourcePermission granting every action on `resource_id`, for the
// ReBAC permission-check responses (distinct from the JWT resource grants in
// `keys`, which are a different, serialized type).
fn grant(resource_id: String) -> ResourcePermission {
    ResourcePermission {
        resource_id,
        permission: keys::ALL_ACTIONS.iter().map(|s| s.to_string()).collect(),
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

#[derive(Default)]
struct Rebac;

#[tonic::async_trait]
impl RebacApi for Rebac {
    async fn create_resource(
        &self,
        _req: Request<CreateResourceRequest>,
    ) -> Result<Response<CreateResourceResponse>, Status> {
        Ok(Response::new(CreateResourceResponse {}))
    }
    async fn delete_resource(
        &self,
        _req: Request<DeleteResourceRequest>,
    ) -> Result<Response<DeleteResourceResponse>, Status> {
        Ok(Response::new(DeleteResourceResponse {}))
    }
}

struct Auth {
    signer: Arc<Signer>,
    dex: Arc<DexVerifier>,
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
        let ids = req.into_inner().resource_id;
        Ok(Response::new(CheckUserPermissionResponse {
            allowed_resource_permission: ids.into_iter().map(grant).collect(),
            denied_resource_permission: vec![],
        }))
    }

    async fn lookup_user_permissions(
        &self,
        req: Request<LookupUserPermissionsRequest>,
    ) -> Result<Response<LookupUserPermissionsResponse>, Status> {
        let filter = req.into_inner().resource_filter;
        Ok(Response::new(LookupUserPermissionsResponse {
            resource_permission: vec![grant(filter)],
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
    /// requested resources. This is what makes `clone`/`push` authorize: the
    /// minted token carries the `resources` grants loreserver's storage and
    /// revision services require.
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

        let resource_ids = req.into_inner().resource_id;
        let minted = self
            .signer
            .mint(
                &self.auth_issuer,
                &self.audience,
                &claims.sub,
                claims.exp,
                &resource_ids,
            )
            .map_err(|e| {
                eprintln!("exchange: minting token failed: {e}");
                Status::internal("token issuance failed")
            })?;

        let user_name = claims
            .preferred_username
            .or(claims.name)
            .or(claims.email)
            .unwrap_or_default();

        Ok(Response::new(
            ExchangeUserTokenForMultiresourceTokenResponse {
                token: Some(UserToken {
                    user_token: minted,
                    expires_at: claims.exp as i64,
                    user_id: claims.sub,
                    user_name,
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

#[tokio::main]
async fn main() -> Result<(), BoxError> {
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

    let dex = Arc::new(DexVerifier::new(dex_issuer.clone(), audience.clone()));

    let auth = Auth {
        signer: signer.clone(),
        dex,
        auth_issuer: auth_issuer.clone(),
        audience: audience.clone(),
    };

    let addr = "0.0.0.0:8080".parse()?;
    println!(
        "kaguya-auth listening on {addr}; issuer={auth_issuer}, audience={audience}, \
         verifying Dex tokens from {dex_issuer}, kid={}",
        signer.kid
    );
    Server::builder()
        .add_service(RebacApiServer::new(Rebac))
        .add_service(UrcAuthApiServer::new(auth))
        .serve(addr)
        .await?;
    Ok(())
}
