// Dex OAuth 2.0 device-flow client (RFC 8628), wrapped so our UCS can offer
// native `lore auth login`. StartAuthSession calls `start` to begin the flow and
// hand the user Dex's verification URL; GetAuthSession calls `poll` on each tick
// until Dex returns a token (the user approved) or a terminal error.
use serde::Deserialize;

const SCOPE: &str = "openid profile email";

#[derive(Deserialize)]
struct Discovery {
    device_authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    verification_uri_complete: Option<String>,
    verification_uri: Option<String>,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    access_token: Option<String>,
    error: Option<String>,
}

/// What a started device authorization gives us. `token_endpoint` is carried so
/// polling never has to re-run discovery.
pub struct DeviceStart {
    pub device_code: String,
    pub login_url: String,
    pub token_endpoint: String,
    pub expires_in: u64,
}

/// The outcome of one poll of the token endpoint.
pub enum Poll {
    /// The user has not finished authorizing; keep polling.
    Pending,
    /// The user approved; the Dex access token.
    Token(String),
    /// A terminal failure (expired, denied, …); stop polling.
    Denied(String),
}

pub struct DexLogin {
    client: reqwest::Client,
    issuer: String,
    client_id: String,
}

impl DexLogin {
    pub fn new(client: reqwest::Client, issuer: String, client_id: String) -> Self {
        DexLogin {
            client,
            issuer,
            client_id,
        }
    }

    async fn discovery(&self) -> Result<Discovery, String> {
        let url = format!("{}/.well-known/openid-configuration", self.issuer);
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

    /// Begin a device authorization: returns the URL to send the user to and the
    /// device_code to poll with.
    pub async fn start(&self) -> Result<DeviceStart, String> {
        let disco = self.discovery().await?;
        let resp: DeviceCodeResponse = self
            .client
            .post(&disco.device_authorization_endpoint)
            .form(&[("client_id", self.client_id.as_str()), ("scope", SCOPE)])
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| format!("device authorization: {e}"))?
            .json()
            .await
            .map_err(|e| format!("device authorization parse: {e}"))?;

        let login_url = resp
            .verification_uri_complete
            .or(resp.verification_uri)
            .ok_or("device authorization returned no verification URI")?;

        Ok(DeviceStart {
            device_code: resp.device_code,
            login_url,
            token_endpoint: disco.token_endpoint,
            expires_in: resp.expires_in,
        })
    }

    /// Poll the token endpoint once. The device-flow token endpoint answers a
    /// pending authorization with HTTP 400 + `error`, so the body is read
    /// regardless of status and classified rather than treated as a hard error.
    pub async fn poll(&self, token_endpoint: &str, device_code: &str) -> Result<Poll, String> {
        let resp = self
            .client
            .post(token_endpoint)
            .form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:device_code",
                ),
                ("device_code", device_code),
                ("client_id", self.client_id.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("token poll: {e}"))?;
        let body = resp.text().await.map_err(|e| format!("token read: {e}"))?;
        let parsed: TokenResponse =
            serde_json::from_str(&body).map_err(|e| format!("token parse: {e}"))?;
        Ok(classify(parsed.id_token, parsed.access_token, parsed.error))
    }
}

/// Classify a token-endpoint response. `authorization_pending` and `slow_down`
/// mean keep polling; a token means done; any other error is terminal. We hand
/// back the id_token (it carries email/email_verified, which the access token
/// may not), falling back to the access token only if no id_token was returned.
fn classify(
    id_token: Option<String>,
    access_token: Option<String>,
    error: Option<String>,
) -> Poll {
    if let Some(token) = id_token.filter(|t| !t.is_empty()) {
        return Poll::Token(token);
    }
    if let Some(token) = access_token.filter(|t| !t.is_empty()) {
        return Poll::Token(token);
    }
    match error.as_deref() {
        Some("authorization_pending") | Some("slow_down") | None => Poll::Pending,
        Some(other) => Poll::Denied(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_token_is_preferred_and_is_success() {
        assert!(matches!(
            classify(Some("idt".to_string()), Some("acc".to_string()), None),
            Poll::Token(t) if t == "idt"
        ));
    }

    #[test]
    fn access_token_is_used_when_no_id_token() {
        assert!(matches!(
            classify(None, Some("acc".to_string()), None),
            Poll::Token(t) if t == "acc"
        ));
    }

    #[test]
    fn authorization_pending_keeps_polling() {
        assert!(matches!(
            classify(None, None, Some("authorization_pending".to_string())),
            Poll::Pending
        ));
        assert!(matches!(
            classify(None, None, Some("slow_down".to_string())),
            Poll::Pending
        ));
    }

    #[test]
    fn other_errors_are_terminal() {
        assert!(matches!(
            classify(None, None, Some("expired_token".to_string())),
            Poll::Denied(e) if e == "expired_token"
        ));
        assert!(matches!(
            classify(None, None, Some("access_denied".to_string())),
            Poll::Denied(_)
        ));
    }

    #[test]
    fn empty_tokens_are_not_success() {
        assert!(matches!(
            classify(Some(String::new()), Some(String::new()), None),
            Poll::Pending
        ));
    }
}
