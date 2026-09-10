// In-memory login-session table for the native device flow.
//
// StartAuthSession begins a device authorization with the OIDC provider and stashes its
// device_code (plus the token endpoint to poll and the caller's client_state)
// under a fresh session_code returned to the client. GetAuthSession looks the
// session back up by session_code, checks the client_state matches, and polls
// the OIDC provider. Sessions are short-lived (the device code expires in minutes) and only
// matter mid-login, so keeping them in memory is fine: an auth-service restart
// just means the user logs in again.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;

struct Session {
    device_code: String,
    token_endpoint: String,
    client_state: String,
    expires_at: Instant,
}

#[derive(Default)]
pub struct Sessions {
    inner: Mutex<HashMap<String, Session>>,
}

impl Sessions {
    pub fn new() -> Self {
        Sessions::default()
    }

    pub fn insert(
        &self,
        session_code: String,
        device_code: String,
        token_endpoint: String,
        client_state: String,
        ttl: Duration,
    ) {
        let mut m = self.inner.lock().unwrap();
        sweep(&mut m);
        m.insert(
            session_code,
            Session {
                device_code,
                token_endpoint,
                client_state,
                expires_at: Instant::now() + ttl,
            },
        );
    }

    /// The `(device_code, token_endpoint)` for a live session whose
    /// `client_state` matches. `None` if the session is unknown, expired, or the
    /// client_state does not match (which binds the poll to the caller that
    /// started it).
    pub fn resolve(&self, session_code: &str, client_state: &str) -> Option<(String, String)> {
        let mut m = self.inner.lock().unwrap();
        sweep(&mut m);
        m.get(session_code).and_then(|s| {
            (s.client_state == client_state && s.expires_at > Instant::now())
                .then(|| (s.device_code.clone(), s.token_endpoint.clone()))
        })
    }

    pub fn remove(&self, session_code: &str) {
        self.inner.lock().unwrap().remove(session_code);
    }
}

fn sweep(m: &mut HashMap<String, Session>) {
    let now = Instant::now();
    m.retain(|_, s| s.expires_at > now);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insert(s: &Sessions, code: &str, state: &str, ttl: Duration) {
        s.insert(
            code.to_string(),
            format!("dc-{code}"),
            "https://idp/token".to_string(),
            state.to_string(),
            ttl,
        );
    }

    #[test]
    fn resolves_a_live_session_with_matching_state() {
        let s = Sessions::new();
        insert(&s, "sess1", "state-a", Duration::from_secs(300));
        assert_eq!(
            s.resolve("sess1", "state-a"),
            Some(("dc-sess1".to_string(), "https://idp/token".to_string()))
        );
    }

    #[test]
    fn wrong_client_state_does_not_resolve() {
        let s = Sessions::new();
        insert(&s, "sess1", "state-a", Duration::from_secs(300));
        assert_eq!(s.resolve("sess1", "state-b"), None);
    }

    #[test]
    fn unknown_session_does_not_resolve() {
        let s = Sessions::new();
        assert_eq!(s.resolve("nope", "state-a"), None);
    }

    #[test]
    fn expired_session_does_not_resolve() {
        let s = Sessions::new();
        insert(&s, "sess1", "state-a", Duration::ZERO);
        assert_eq!(s.resolve("sess1", "state-a"), None);
    }

    #[test]
    fn removed_session_is_gone() {
        let s = Sessions::new();
        insert(&s, "sess1", "state-a", Duration::from_secs(300));
        s.remove("sess1");
        assert_eq!(s.resolve("sess1", "state-a"), None);
    }
}
