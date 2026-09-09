// Publication of the combined JWKS loreserver reads.
//
// loreserver has a single JWKS source but must verify two kinds of token:
//   - the exchanged tokens we sign (issuer = this service), on storage/revision;
//   - the raw Dex identity token (issuer = Dex), which the client sends to the
//     authn-only repository service before it knows the repository id and so
//     cannot yet exchange (see connection.rs: exchange runs only once the repo
//     is known).
// So we publish one JWKS carrying our key plus Dex's. loreserver trusts both
// issuers (jwt_issuer lists both) and finds each token's key by kid here.
use std::error::Error;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

type BoxError = Box<dyn Error + Send + Sync>;

const JWKS_FILE: &str = "jwks.json";

#[derive(Deserialize)]
struct DiscoveryDoc {
    jwks_uri: String,
}

/// Fetch an issuer's JWKS as raw JSON via OIDC discovery. Returned verbatim so
/// both verification (`verify`) and publication see exactly what Dex serves.
pub async fn fetch_jwks(client: &reqwest::Client, issuer: &str) -> Result<Value, String> {
    let discovery_url = format!("{issuer}/.well-known/openid-configuration");
    let discovery: DiscoveryDoc = client
        .get(&discovery_url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("discovery {discovery_url}: {e}"))?
        .json()
        .await
        .map_err(|e| format!("discovery parse: {e}"))?;

    client
        .get(&discovery.jwks_uri)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| format!("jwks {}: {e}", discovery.jwks_uri))?
        .json()
        .await
        .map_err(|e| format!("jwks parse: {e}"))
}

/// Merge our own signing key with an issuer's keys into one JWKS document. Our
/// key comes first.
fn combine(own_jwk: &Value, dex_jwks: &Value) -> Value {
    let mut keys = vec![own_jwk.clone()];
    if let Some(arr) = dex_jwks.get("keys").and_then(|k| k.as_array()) {
        keys.extend(arr.iter().cloned());
    }
    serde_json::json!({ "keys": keys })
}

/// Write the combined JWKS (our key + Dex's) to `dir/jwks.json`.
///
/// If Dex is unreachable the file is still written with our key alone, so
/// exchanged tokens keep verifying and the healthcheck (file exists) passes; the
/// periodic refresh fills Dex's keys in once it recovers and tracks Dex key
/// rotation.
pub async fn publish(
    dir: &Path,
    client: &reqwest::Client,
    dex_issuer: &str,
    own_jwk: &Value,
) -> Result<(), BoxError> {
    let dex = match fetch_jwks(client, dex_issuer).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("jwks: Dex keys unavailable, publishing own key only: {e}");
            serde_json::json!({ "keys": [] })
        }
    };
    let doc = combine(own_jwk, &dex);
    std::fs::write(dir.join(JWKS_FILE), doc.to_string().as_bytes())?;
    Ok(())
}

/// Re-publish the combined JWKS on an interval, so Dex key rotation (and a Dex
/// that was down at startup) is picked up without restarting the service.
pub fn spawn_refresh(
    dir: PathBuf,
    client: reqwest::Client,
    dex_issuer: String,
    own_jwk: Value,
    every: Duration,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(every).await;
            if let Err(e) = publish(&dir, &client, &dex_issuer, &own_jwk).await {
                eprintln!("jwks: periodic refresh failed: {e}");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::jwk::JwkSet;
    use serde_json::json;

    fn jwk(kid: &str) -> Value {
        // Shape only; the crypto round-trip is covered in `keys`/`verify`.
        json!({"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": "AQAB", "e": "AQAB"})
    }

    // The combined document must carry our key and every Dex key, and parse as
    // the JwkSet loreserver deserializes, with each key findable by its kid.
    #[test]
    fn combine_includes_own_and_dex_keys() {
        let own = jwk("ours");
        let dex = json!({"keys": [jwk("dex-1"), jwk("dex-2")]});

        let combined = combine(&own, &dex);
        let set: JwkSet = serde_json::from_value(combined).expect("combined parses as JwkSet");

        assert_eq!(set.keys.len(), 3);
        assert!(set.find("ours").is_some(), "our key must be present");
        assert!(set.find("dex-1").is_some(), "dex keys must be present");
        assert!(set.find("dex-2").is_some());
    }

    // Dex unreachable is modeled as an empty key set: our key still stands alone.
    #[test]
    fn combine_with_no_dex_keys_keeps_our_key() {
        let combined = combine(&jwk("ours"), &json!({"keys": []}));
        let set: JwkSet = serde_json::from_value(combined).unwrap();
        assert_eq!(set.keys.len(), 1);
        assert!(set.find("ours").is_some());
    }
}
