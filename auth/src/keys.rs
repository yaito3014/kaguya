// Signing key management and Lore token minting.
//
// The auth service is the issuer of the "multiresource" tokens Lore verifies:
// the client logs in to the OIDC provider, exchanges that identity here, and we hand back a
// token signed with *our* key that carries the per-repository `resources` claim
// Lore's storage/revision authorization (`verify_authorization`) requires.
//
// The private key is the source of truth, persisted (PKCS#8 PEM) in a shared
// volume. Our public key is published as one JWK (`own_jwk`); the combined JWKS
// loreserver reads (this key plus the IdP's, see `jwks`) is assembled elsewhere.
// `kid` is the RFC 7638 thumbprint, so it changes if and only if the key does.
use std::error::Error;
use std::path::Path;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::encode;
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::pkcs8::LineEnding;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use rsa::RsaPublicKey;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;

type BoxError = Box<dyn Error + Send + Sync>;

const KEY_FILE: &str = "signing_key.pem";
const RSA_BITS: usize = 2048;

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ResourceGrant {
    pub resource_id: String,
    pub permission: Vec<String>,
}

/// Claims of a minted Lore token. Mirrors the subset of Lore's
/// `AuthorizationToken` that its verification reads (the registered claims plus
/// the `resources` grant list), and carries the display claims the lore CLI
/// requires when it decodes the exchanged token: `name`, `preferred_username`
/// and `is_service_account` (the deployed CLI treats `name` as mandatory, so we
/// always emit it — carried over from the verified OIDC identity).
#[derive(Serialize, Deserialize, Debug)]
pub struct MintedClaims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub iat: u64,
    pub exp: u64,
    pub name: String,
    pub preferred_username: String,
    pub is_service_account: bool,
    pub resources: Vec<ResourceGrant>,
}

pub struct Signer {
    encoding_key: EncodingKey,
    pub kid: String,
    own_jwk: Value,
}

impl Signer {
    /// Load the persisted signing key from `dir`, generating one on first run.
    /// Only the private key is written here; the published JWKS is assembled by
    /// the caller (it also carries the IdP's keys).
    pub fn load_or_generate(dir: &Path) -> Result<Signer, BoxError> {
        std::fs::create_dir_all(dir)?;
        let key_path = dir.join(KEY_FILE);

        let pem = if key_path.exists() {
            std::fs::read_to_string(&key_path)?
        } else {
            let mut rng = rand::thread_rng();
            let private = RsaPrivateKey::new(&mut rng, RSA_BITS)?;
            let pem = private.to_pkcs8_pem(LineEnding::LF)?.to_string();
            std::fs::write(&key_path, pem.as_bytes())?;
            pem
        };

        Signer::from_pkcs8_pem(&pem)
    }

    /// Build a signer from a PKCS#8 PEM private key. Pure: derives the kid and
    /// public JWK from the key, no I/O.
    fn from_pkcs8_pem(pem: &str) -> Result<Signer, BoxError> {
        let private = RsaPrivateKey::from_pkcs8_pem(pem)?;
        let public = RsaPublicKey::from(&private);

        let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
        let kid = thumbprint(&n, &e);
        let own_jwk = build_jwk(&kid, &n, &e);

        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())?;
        Ok(Signer {
            encoding_key,
            kid,
            own_jwk,
        })
    }

    /// Our public signing key as a single JWK, for embedding in the combined
    /// JWKS loreserver reads.
    pub fn own_jwk(&self) -> &Value {
        &self.own_jwk
    }

    /// Mint a Lore token for `subject` (with the display `name` and
    /// `preferred_username` carried from the verified identity), carrying the
    /// caller-supplied `resources` grants (already scoped to what the subject is
    /// allowed, with per-role permissions), expiring at `exp`.
    #[allow(clippy::too_many_arguments)]
    pub fn mint(
        &self,
        issuer: &str,
        audience: &str,
        subject: &str,
        name: &str,
        preferred_username: &str,
        exp: u64,
        resources: Vec<ResourceGrant>,
    ) -> Result<String, BoxError> {
        let claims = MintedClaims {
            iss: issuer.to_string(),
            sub: subject.to_string(),
            aud: vec![audience.to_string()],
            iat: now_secs(),
            exp,
            name: name.to_string(),
            preferred_username: preferred_username.to_string(),
            is_service_account: false,
            resources,
        };
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid.clone());
        Ok(encode(&header, &claims, &self.encoding_key)?)
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn build_jwk(kid: &str, n: &str, e: &str) -> Value {
    serde_json::json!({
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": n,
        "e": e,
    })
}

/// RFC 7638 JWK thumbprint for an RSA key: SHA-256 of the canonical member
/// ordering (`e`, `kty`, `n`), base64url-encoded.
fn thumbprint(n: &str, e: &str) -> String {
    let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::decode;
    use jsonwebtoken::jwk::Jwk;
    use jsonwebtoken::DecodingKey;
    use jsonwebtoken::Validation;

    const ISS: &str = "https://auth.lore.example.com";
    const AUD: &str = "lore.example.com";

    fn signer() -> Signer {
        let dir = std::env::temp_dir().join(format!("kaguya-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Signer::load_or_generate(&dir).expect("generate signer")
    }

    fn grants(ids: &[&str]) -> Vec<ResourceGrant> {
        ids.iter()
            .map(|id| ResourceGrant {
                resource_id: id.to_string(),
                permission: vec!["read".to_string(), "write".to_string()],
            })
            .collect()
    }

    fn decoding_key(signer: &Signer) -> DecodingKey {
        let jwk: Jwk = serde_json::from_value(signer.own_jwk().clone()).expect("own jwk parses");
        DecodingKey::from_jwk(&jwk).expect("decoding key from jwk")
    }

    fn validation() -> Validation {
        let mut v = Validation::new(Algorithm::RS256);
        v.set_audience(&[AUD]);
        v.set_issuer(&[ISS]);
        v.validate_exp = true;
        v
    }

    // The end-to-end contract: a token we mint verifies against the JWK we
    // publish (the same Jwk/from_jwk path loreserver uses) and carries the
    // requested resource grants.
    #[test]
    fn minted_token_verifies_against_published_jwk() {
        let signer = signer();
        let exp = now_secs() + 3600;

        let token = signer
            .mint(ISS, AUD, "user-1", "User One", "user1", exp, grants(&["urc-abc", "urc-def"]))
            .unwrap();
        let data = decode::<MintedClaims>(&token, &decoding_key(&signer), &validation())
            .expect("minted token must verify against its own JWK");

        assert_eq!(data.claims.iss, ISS);
        assert_eq!(data.claims.aud, vec![AUD.to_string()]);
        assert_eq!(data.claims.sub, "user-1");
        assert_eq!(data.claims.exp, exp);
        // The deployed lore CLI requires `name` when it decodes the exchanged token.
        assert_eq!(data.claims.name, "User One");
        assert_eq!(data.claims.preferred_username, "user1");
        let ids: Vec<&str> = data
            .claims
            .resources
            .iter()
            .map(|r| r.resource_id.as_str())
            .collect();
        assert_eq!(ids, vec!["urc-abc", "urc-def"]);
        assert!(data
            .claims
            .resources
            .iter()
            .all(|r| r.permission == vec!["read", "write"]));
    }

    // Mirror of loreserver's `verify_authorization`: the resource the client will
    // dial (`urc-{repository}`) must be present in the token's `resources`.
    #[test]
    fn minted_token_authorizes_the_requested_repository() {
        let signer = signer();
        let repo = "urc-0194b726b34e72b0b45550b88a967076";
        let token = signer
            .mint(ISS, AUD, "u", "U", "u", now_secs() + 60, grants(&[repo]))
            .unwrap();
        let data = decode::<MintedClaims>(&token, &decoding_key(&signer), &validation()).unwrap();
        assert!(data.claims.resources.iter().any(|r| r.resource_id == repo));
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let signer = signer();
        let token = signer
            .mint(ISS, "someone-else", "u", "U", "u", now_secs() + 60, grants(&["urc-x"]))
            .unwrap();
        decode::<MintedClaims>(&token, &decoding_key(&signer), &validation())
            .expect_err("a token minted for another audience must not verify");
    }

    #[test]
    fn expired_token_is_rejected() {
        let signer = signer();
        let token = signer
            .mint(ISS, AUD, "u", "U", "u", now_secs() - 3600, grants(&["urc-x"]))
            .unwrap();
        decode::<MintedClaims>(&token, &decoding_key(&signer), &validation())
            .expect_err("an expired token must not verify");
    }

    // A persisted key round-trips to the same kid and JWK, so loreserver's cached
    // key stays valid across auth-service restarts.
    #[test]
    fn kid_is_stable_across_reload() {
        let dir = std::env::temp_dir().join(format!("kaguya-reload-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = Signer::load_or_generate(&dir).unwrap();
        let second = Signer::load_or_generate(&dir).unwrap();
        assert_eq!(first.kid, second.kid);
        assert_eq!(first.own_jwk(), second.own_jwk());
    }
}
