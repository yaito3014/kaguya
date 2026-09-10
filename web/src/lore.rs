//! gRPC read client to loreserver (internal, h2c). Read-only browsing:
//! repositories, branches, history, tree. Content (StorageService.Get) is a
//! later increment.
//!
//! Auth: every call carries `authorization: Bearer <token>`. Repo-scoped calls
//! also carry the repository id as binary metadata `lore-partition-bin` (+ the
//! `urc-repository-id-bin` fallback), value = raw repository-id bytes.
use serde::Serialize;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::Request;

use crate::pb::lore::repository::v1::repository_service_client::RepositoryServiceClient;
use crate::pb::lore::repository::v1::RepositoryListRequest;

pub struct LoreClient {
    endpoint: String,
}

#[derive(Serialize)]
pub struct RepoSummary {
    /// Repository id as lowercase hex (the form `lore` prints and we use in URLs).
    pub id: String,
    pub name: String,
    pub description: String,
    pub default_branch: String,
}

impl LoreClient {
    pub fn new(endpoint: String) -> Self {
        LoreClient { endpoint }
    }

    async fn repository(&self, token: &str) -> Result<RepositoryServiceClient<Channel>, String> {
        let _ = token;
        RepositoryServiceClient::connect(self.endpoint.clone())
            .await
            .map_err(|e| format!("lore connect: {e}"))
    }

    /// List the repositories the caller may access. loreserver filters by the
    /// caller's ReBAC grants (via kaguya-auth's LookupUserPermissions), so this
    /// returns only the user's repositories.
    pub async fn list_repos(&self, token: &str) -> Result<Vec<RepoSummary>, String> {
        let mut client = self.repository(token).await?;
        let mut req = Request::new(RepositoryListRequest { creator: None });
        set_bearer(&mut req, token)?;
        let mut stream = client
            .repository_list(req)
            .await
            .map_err(|e| format!("repository_list: {e}"))?
            .into_inner();

        let mut repos = Vec::new();
        while let Some(msg) = stream
            .message()
            .await
            .map_err(|e| format!("repository_list stream: {e}"))?
        {
            if let Some(r) = msg.repository {
                repos.push(RepoSummary {
                    id: hex(&r.id),
                    name: r.name,
                    description: r.description,
                    default_branch: r.default_branch_name,
                });
            }
        }
        Ok(repos)
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[allow(dead_code)] // used by repo-scoped browsing (next increment)
pub fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd-length hex".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

fn set_bearer<T>(req: &mut Request<T>, token: &str) -> Result<(), String> {
    let value = format!("Bearer {token}")
        .parse()
        .map_err(|_| "invalid bearer token".to_string())?;
    req.metadata_mut().insert("authorization", value);
    Ok(())
}

/// Attach bearer + the repository-id binary metadata for repo-scoped calls.
#[allow(dead_code)]
fn set_repo_scope<T>(req: &mut Request<T>, token: &str, repo_id: &[u8]) -> Result<(), String> {
    set_bearer(req, token)?;
    let id = MetadataValue::from_bytes(repo_id);
    req.metadata_mut().insert_bin("lore-partition-bin", id.clone());
    req.metadata_mut()
        .insert_bin("urc-repository-id-bin", id);
    Ok(())
}
