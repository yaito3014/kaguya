// kaguya-auth: minimal all-allow ReBAC/auth service for Lore.
// Implements the four methods loreserver actually calls (RebacApi.CreateResource
// / DeleteResource, UrcAuthApi.CheckUserPermission / LookupUserPermissions).
// Authentication is enforced upstream by loreserver's [server.auth] JWT check;
// this service grants every action to any request that reaches it, so it must
// stay on the internal compose network only.
use base64::Engine;
use tonic::{transport::Server, Request, Response, Status};

pub mod ucs_auth {
    include!(concat!(env!("OUT_DIR"), "/ucs.auth.rs"));
}
pub mod epic_urc {
    include!(concat!(env!("OUT_DIR"), "/epic_urc.rs"));
}

use ucs_auth::rebac_api_server::{RebacApi, RebacApiServer};
use ucs_auth::{
    CreateResourceRequest, CreateResourceResponse, DeleteResourceRequest, DeleteResourceResponse,
};
use epic_urc::urc_auth_api_server::{UrcAuthApi, UrcAuthApiServer};
use epic_urc::*;

// Actions loreserver names in check_repository_access; everything else is an
// existence check (action = None), satisfied by returning the resource_id.
const ALL_ACTIONS: &[&str] = &["obliterate", "presign"];

fn grant(resource_id: String) -> ResourcePermission {
    ResourcePermission {
        resource_id,
        permission: ALL_ACTIONS.iter().map(|s| s.to_string()).collect(),
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

// Read the `exp` claim from a JWT without verifying the signature (loreserver's
// [server.auth] does the real verification). Returns 0 if it can't be parsed.
fn jwt_exp(token: &str) -> i64 {
    let Some(payload) = token.split('.').nth(1) else { return 0 };
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) else {
        return 0;
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else { return 0 };
    v.get("exp").and_then(|e| e.as_i64()).unwrap_or(0)
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

#[derive(Default)]
struct Auth;

#[tonic::async_trait]
impl UrcAuthApi for Auth {
    async fn health_check(
        &self,
        _req: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse { status: "ok".into() }))
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
        Err(Status::unimplemented("exchange_external_token_for_user_token"))
    }
    async fn exchange_api_key_for_user_token(
        &self,
        _req: Request<ExchangeApiKeyForUserTokenRequest>,
    ) -> Result<Response<ExchangeApiKeyForUserTokenResponse>, Status> {
        Err(Status::unimplemented("exchange_api_key_for_user_token"))
    }
    async fn exchange_user_token_for_multiresource_token(
        &self,
        req: Request<ExchangeUserTokenForMultiresourceTokenRequest>,
    ) -> Result<Response<ExchangeUserTokenForMultiresourceTokenResponse>, Status> {
        // Pass-through: hand the caller's own JWT back as the multiresource
        // token. loreserver re-verifies it via [server.auth]; authorization is
        // granted separately by check_user_permission.
        let token = bearer(&req);
        let expires_at = jwt_exp(&token);
        Ok(Response::new(ExchangeUserTokenForMultiresourceTokenResponse {
            token: Some(UserToken {
                user_token: token,
                expires_at,
                user_id: String::new(),
                user_name: String::new(),
            }),
        }))
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "0.0.0.0:8080".parse()?;
    println!("kaguya-auth listening on {addr}");
    Server::builder()
        .add_service(RebacApiServer::new(Rebac))
        .add_service(UrcAuthApiServer::new(Auth))
        .serve(addr)
        .await?;
    Ok(())
}
