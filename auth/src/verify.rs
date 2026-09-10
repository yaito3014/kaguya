// Token verification: the incoming identity bearer, whether Dex-issued (the
// get-token.sh path) or one we minted ourselves (native login / a forwarded
// exchanged token).
//
// Before minting a repository-scoped token for an identity we verify the
// bearer's signature, issuer, audience and expiry, so a forged or foreign bearer
// cannot obtain access. `DexVerifier` checks Dex-signed tokens against Dex's JWKS
// (fetched via OIDC discovery and cached; an unknown `kid` triggers one refetch,
// covering key rotation); `SelfVerifier` checks tokens we signed against our own
// key; `Identity` tries ours first, then Dex.
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use jsonwebtoken::decode;
use jsonwebtoken::decode_header;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::Algorithm;
use jsonwebtoken::DecodingKey;
use jsonwebtoken::Validation;
use serde::Deserialize;
use tokio::sync::RwLock;

/// The identity claims we read off a verified token, whether a Dex identity
/// token or one we minted ourselves. `sub`/`exp` carry into the minted Lore
/// token; the optional display fields populate the exchange response.
#[derive(Deserialize, Debug)]
pub struct IdentityClaims {
    pub sub: String,
    pub exp: u64,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
}

impl IdentityClaims {
    /// The canonical account id. A **verified** email (lowercased) unifies the
    /// same person's logins across connectors (password, GitHub, …) into one
    /// account; without a verified email we fall back to the connector-specific
    /// subject, so an unverified or missing email can never collide with
    /// someone else's account.
    pub fn canonical_subject(&self) -> String {
        match (&self.email, self.email_verified) {
            (Some(email), Some(true)) if !email.is_empty() => email.to_lowercase(),
            _ => self.sub.clone(),
        }
    }
}

#[cfg(test)]
mod canonical_subject_tests {
    use super::IdentityClaims;

    fn claims(email: Option<&str>, verified: Option<bool>) -> IdentityClaims {
        IdentityClaims {
            sub: "Cixxxxxxx".to_string(),
            exp: 0,
            preferred_username: None,
            name: None,
            email: email.map(String::from),
            email_verified: verified,
        }
    }

    #[test]
    fn verified_email_is_the_canonical_subject_lowercased() {
        assert_eq!(
            claims(Some("User@Example.com"), Some(true)).canonical_subject(),
            "user@example.com"
        );
    }

    #[test]
    fn unverified_or_missing_email_falls_back_to_the_connector_subject() {
        assert_eq!(
            claims(Some("u@example.com"), Some(false)).canonical_subject(),
            "Cixxxxxxx"
        );
        assert_eq!(claims(Some("u@example.com"), None).canonical_subject(), "Cixxxxxxx");
        assert_eq!(claims(None, Some(true)).canonical_subject(), "Cixxxxxxx");
    }
}

#[derive(Debug)]
pub enum VerifyError {
    /// The bearer is not a well-formed JWT, or carries no `kid`.
    Malformed(String),
    /// No key with the token's `kid` in Dex's JWKS, even after a refresh.
    UnknownKid(String),
    /// Dex's JWKS could not be fetched or parsed.
    Jwks(String),
    /// Signature, issuer, audience or expiry did not check out.
    Invalid(String),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Malformed(m) => write!(f, "malformed token: {m}"),
            VerifyError::UnknownKid(kid) => write!(f, "no Dex key for kid {kid}"),
            VerifyError::Jwks(m) => write!(f, "Dex JWKS unavailable: {m}"),
            VerifyError::Invalid(m) => write!(f, "token rejected: {m}"),
        }
    }
}

impl Error for VerifyError {}

pub struct DexVerifier {
    issuer: String,
    audiences: Vec<String>,
    client: reqwest::Client,
    jwks: RwLock<Option<JwkSet>>,
}

impl DexVerifier {
    /// `audiences` is every Dex client id whose tokens we accept: the CLI/device
    /// client (LORE_HOST) and the web frontend client, which have different `aud`.
    pub fn new(issuer: String, audiences: Vec<String>) -> Self {
        DexVerifier {
            issuer,
            audiences,
            client: reqwest::Client::new(),
            jwks: RwLock::new(None),
        }
    }

    /// Verify a Dex bearer token, refetching the JWKS once if the token's key id
    /// is not already cached.
    pub async fn verify(&self, token: &str) -> Result<IdentityClaims, VerifyError> {
        let kid = decode_header(token)
            .map_err(|e| VerifyError::Malformed(e.to_string()))?
            .kid
            .ok_or_else(|| VerifyError::Malformed("no kid in header".into()))?;

        if let Some(jwks) = self.jwks.read().await.as_ref() {
            if jwks.find(&kid).is_some() {
                return verify_with_jwks(token, jwks, &self.issuer, &self.audiences);
            }
        }

        let fetched = self.fetch_jwks().await?;
        let result = verify_with_jwks(token, &fetched, &self.issuer, &self.audiences);
        *self.jwks.write().await = Some(fetched);
        result
    }

    async fn fetch_jwks(&self) -> Result<JwkSet, VerifyError> {
        let value = crate::jwks::fetch_jwks(&self.client, &self.issuer)
            .await
            .map_err(VerifyError::Jwks)?;
        serde_json::from_value(value).map_err(|e| VerifyError::Jwks(format!("jwks parse: {e}")))
    }
}

/// Verifier for tokens this service itself signed (the exchanged authz tokens),
/// using our own public key. Lets us read the subject back out of a token
/// loreserver forwards to the ReBAC RPCs without going to Dex.
pub struct SelfVerifier {
    key: DecodingKey,
    issuer: String,
    audience: String,
}

impl SelfVerifier {
    pub fn new(
        own_jwk: &serde_json::Value,
        issuer: String,
        audience: String,
    ) -> Result<Self, VerifyError> {
        let jwk: jsonwebtoken::jwk::Jwk = serde_json::from_value(own_jwk.clone())
            .map_err(|e| VerifyError::Jwks(format!("own jwk: {e}")))?;
        let key = DecodingKey::from_jwk(&jwk)
            .map_err(|e| VerifyError::Jwks(format!("own jwk key: {e}")))?;
        Ok(SelfVerifier {
            key,
            issuer,
            audience,
        })
    }

    /// The identity claims of a token we signed, or `None` if it is not one of
    /// ours (wrong signature/issuer/audience or expired).
    pub fn claims(&self, token: &str) -> Option<IdentityClaims> {
        let mut v = Validation::new(Algorithm::RS256);
        v.set_issuer(&[self.issuer.as_str()]);
        v.set_audience(&[self.audience.as_str()]);
        v.validate_exp = true;
        decode::<IdentityClaims>(token, &self.key, &v)
            .ok()
            .map(|d| d.claims)
    }
}

/// Resolves the authenticated identity from whatever bearer we are handed: a
/// token we signed (an authn token from native login, or an exchanged authz
/// token loreserver forwards) or a raw Dex identity token (the get-token.sh
/// path). Both are verified; an unverifiable bearer yields an error.
pub struct Identity {
    pub self_verifier: SelfVerifier,
    pub dex: Arc<DexVerifier>,
}

impl Identity {
    /// The full identity claims, trying our own key first, then Dex.
    pub async fn claims(&self, bearer: &str) -> Result<IdentityClaims, VerifyError> {
        if let Some(claims) = self.self_verifier.claims(bearer) {
            return Ok(claims);
        }
        self.dex.verify(bearer).await
    }

    pub async fn subject(&self, bearer: &str) -> Result<String, VerifyError> {
        Ok(self.claims(bearer).await?.sub)
    }
}

/// Verify a token against an already-resolved JWKS. Pure: no I/O, no caching, so
/// the verification rules are testable without a live Dex.
pub fn verify_with_jwks(
    token: &str,
    jwks: &JwkSet,
    issuer: &str,
    audiences: &[String],
) -> Result<IdentityClaims, VerifyError> {
    let kid = decode_header(token)
        .map_err(|e| VerifyError::Malformed(e.to_string()))?
        .kid
        .ok_or_else(|| VerifyError::Malformed("no kid in header".into()))?;

    let jwk = jwks
        .find(&kid)
        .ok_or_else(|| VerifyError::UnknownKid(kid.clone()))?;
    let key =
        DecodingKey::from_jwk(jwk).map_err(|e| VerifyError::Jwks(format!("bad jwk {kid}: {e}")))?;

    // The key type is fixed by the JWK (RSA), and the algorithm is pinned to
    // RS256 here rather than taken from the token header, so a token cannot pick
    // its own algorithm (the classic RSA/HMAC confusion).
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(audiences);
    validation.validate_exp = true;

    decode::<IdentityClaims>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| VerifyError::Invalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use jsonwebtoken::encode;
    use jsonwebtoken::EncodingKey;
    use jsonwebtoken::Header;
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::pkcs8::LineEnding;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use rsa::RsaPublicKey;
    use serde_json::json;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    const ISS: &str = "https://dex.example.com/dex";
    const AUD: &str = "lore.example.com";
    const KID: &str = "test-key";

    // A stand-in Dex: an RSA key, plus the JWKS that publishes it. Kept entirely
    // local so the verification rules are exercised without a network.
    struct FakeIdp {
        encoding: EncodingKey,
        jwks: JwkSet,
    }

    fn fake_idp() -> FakeIdp {
        let mut rng = rand::thread_rng();
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public = RsaPublicKey::from(&private);
        let pem = private.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
        // Round-trip through PKCS#1 to confirm we could, but the JWKS is built
        // from the raw components, matching what a real provider serves.
        let _ = public.to_pkcs1_der().unwrap();

        let n = URL_SAFE_NO_PAD.encode(public.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(public.e().to_bytes_be());
        let jwks: JwkSet = serde_json::from_value(json!({
            "keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID, "n": n, "e": e}]
        }))
        .unwrap();

        FakeIdp {
            encoding: EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
            jwks,
        }
    }

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn sign(idp: &FakeIdp, claims: serde_json::Value) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(KID.to_string());
        encode(&header, &claims, &idp.encoding).unwrap()
    }

    fn valid_claims() -> serde_json::Value {
        json!({"iss": ISS, "aud": AUD, "sub": "abc-123", "exp": now() + 3600, "iat": now()})
    }

    #[test]
    fn valid_dex_token_is_accepted() {
        let idp = fake_idp();
        let token = sign(&idp, valid_claims());
        let claims = verify_with_jwks(&token, &idp.jwks, ISS, &[AUD.to_string()]).expect("valid token accepted");
        assert_eq!(claims.sub, "abc-123");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let idp = fake_idp();
        let mut token = sign(&idp, valid_claims());
        // Flip the last signature character.
        let last = token.pop().unwrap();
        token.push(if last == 'A' { 'B' } else { 'A' });
        assert!(matches!(
            verify_with_jwks(&token, &idp.jwks, ISS, &[AUD.to_string()]),
            Err(VerifyError::Invalid(_))
        ));
    }

    #[test]
    fn wrong_audience_is_rejected() {
        let idp = fake_idp();
        let token = sign(&idp, json!({"iss": ISS, "aud": "other", "sub": "s", "exp": now() + 60}));
        assert!(matches!(
            verify_with_jwks(&token, &idp.jwks, ISS, &[AUD.to_string()]),
            Err(VerifyError::Invalid(_))
        ));
    }

    #[test]
    fn wrong_issuer_is_rejected() {
        let idp = fake_idp();
        let token = sign(
            &idp,
            json!({"iss": "https://evil.example.com", "aud": AUD, "sub": "s", "exp": now() + 60}),
        );
        assert!(matches!(
            verify_with_jwks(&token, &idp.jwks, ISS, &[AUD.to_string()]),
            Err(VerifyError::Invalid(_))
        ));
    }

    #[test]
    fn expired_token_is_rejected() {
        let idp = fake_idp();
        let token = sign(&idp, json!({"iss": ISS, "aud": AUD, "sub": "s", "exp": now() - 3600}));
        assert!(matches!(
            verify_with_jwks(&token, &idp.jwks, ISS, &[AUD.to_string()]),
            Err(VerifyError::Invalid(_))
        ));
    }

    #[test]
    fn unknown_kid_is_reported() {
        let idp = fake_idp();
        let other = fake_idp(); // different key, but its JWKS still advertises KID
        let token = sign(&other, valid_claims());
        // Same kid, different key material -> signature fails, not an unknown kid.
        assert!(matches!(
            verify_with_jwks(&token, &idp.jwks, ISS, &[AUD.to_string()]),
            Err(VerifyError::Invalid(_))
        ));

        // A token whose kid is absent from the JWKS is an unknown kid.
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("nonexistent".to_string());
        let token = encode(&header, &valid_claims(), &idp.encoding).unwrap();
        assert!(matches!(
            verify_with_jwks(&token, &idp.jwks, ISS, &[AUD.to_string()]),
            Err(VerifyError::UnknownKid(_))
        ));
    }
}
