// Publication of the JWKS loreserver reads.
//
// loreserver trusts a single issuer, this service, so the published JWKS carries
// only our signing key. Dex-issued tokens are never presented to loreserver
// (native login mints our own token); Dex tokens are verified separately, during
// login, by `verify::DexVerifier`, which fetches Dex's JWKS through `fetch_jwks`
// below. Our key is static, so the file is written once at startup.
use std::error::Error;
use std::path::Path;

use serde::Deserialize;
use serde_json::Value;

type BoxError = Box<dyn Error + Send + Sync>;

const JWKS_FILE: &str = "jwks.json";

#[derive(Deserialize)]
struct DiscoveryDoc {
    jwks_uri: String,
}

/// Fetch an issuer's JWKS as raw JSON via OIDC discovery. Used by `DexVerifier`
/// to verify Dex identity tokens during login.
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

/// Write the JWKS (our signing key only) to `dir/jwks.json` for loreserver to
/// read via file://.
pub fn publish(dir: &Path, own_jwk: &Value) -> Result<(), BoxError> {
    let doc = serde_json::json!({ "keys": [own_jwk] });
    std::fs::write(dir.join(JWKS_FILE), doc.to_string().as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::jwk::JwkSet;
    use serde_json::json;

    #[test]
    fn publishes_our_key_as_a_parseable_jwks() {
        let dir = std::env::temp_dir().join(format!("kaguya-jwks-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let own = json!({"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "ours", "n": "AQAB", "e": "AQAB"});

        publish(&dir, &own).unwrap();

        let written = std::fs::read_to_string(dir.join(JWKS_FILE)).unwrap();
        let set: JwkSet = serde_json::from_str(&written).expect("published file parses as JwkSet");
        assert_eq!(set.keys.len(), 1);
        assert!(set.find("ours").is_some());
    }
}
