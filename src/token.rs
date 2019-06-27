extern crate data_encoding;
extern crate jsonwebtoken;

use crate::config;
use data_encoding::{BASE64, BASE64URL_NOPAD};
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{encode, Header, Validation};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{Key, Nonce};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    exp: u64,
}

lazy_static! {
    // Load this value into a static var so we don't have to decode it every
    // time.
    static ref SECRET_KEY: Key = {
        Key::from_slice(
            &BASE64
                .decode(config::CONFIG.jwt.encryption_secret.as_bytes())
                .expect("Couldn't decode JWT encryption secret"),
        )
        .expect("Couldn't read into JWT key")
    };
}

pub fn generate(sub: &str, expiry: u64) -> String {
    generate_inner(&config::CONFIG.jwt, &SECRET_KEY, sub, expiry)
}

fn generate_inner(jwt_config: &config::Jwt, key: &Key, sub: &str, expiry: u64) -> String {
    use std::time::SystemTime;

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        sub: sub.to_string(),
        iss: jwt_config.iss.clone(),
        exp: timestamp + expiry,
    };

    match encode(&Header::default(), &claims, jwt_config.jwt_secret.as_ref()) {
        Ok(token) => {
            let nonce = secretbox::gen_nonce();
            let ciphertext = secretbox::seal(token.as_bytes(), &nonce, key);
            // Nonce is first 24 bytes, or 32 chars
            // Remaining bytes are ciphertext.
            format!(
                "{}{}",
                BASE64URL_NOPAD.encode(nonce.as_ref()).to_string(),
                BASE64URL_NOPAD.encode(&ciphertext).to_string(),
            )
        }
        Err(err) => panic!("error generating jwt: {:?}", err),
    }
}

#[derive(Debug, Fail)]
pub enum TokenError {
    #[fail(display = "failed to decode token")]
    DecodingError,
    #[fail(display = "invalid token")]
    InvalidToken,
    #[fail(display = "utf8 decode failure")]
    Utf8Decoding,
    #[fail(display = "invalid token length (expecting at least 32 chars")]
    InvalidTokenLength,
}

impl From<data_encoding::DecodeError> for TokenError {
    fn from(_error: data_encoding::DecodeError) -> Self {
        TokenError::DecodingError
    }
}

impl From<std::string::FromUtf8Error> for TokenError {
    fn from(_error: std::string::FromUtf8Error) -> Self {
        TokenError::Utf8Decoding
    }
}

impl From<()> for TokenError {
    fn from(_error: ()) -> Self {
        TokenError::DecodingError
    }
}

pub fn decode_into_sub(token: &str) -> Result<String, TokenError> {
    decode_into_sub_inner(&config::CONFIG.jwt, &SECRET_KEY, token)
}

fn decode_into_sub_inner(
    jwt_config: &config::Jwt,
    key: &Key,
    token: &str,
) -> Result<String, TokenError> {
    if token.len() < 32 {
        return Err(TokenError::InvalidTokenLength)
    }
    // First 24 bytes (32 chars) are the nonce.
    let nonce = Nonce::from_slice(&BASE64URL_NOPAD.decode(token[..32].as_bytes())?).unwrap();
    // Remaining bytes are the ciphertext.
    let ciphertext = BASE64URL_NOPAD.decode(token[32..].as_bytes())?;
    let jwt = String::from_utf8(secretbox::open(&ciphertext, &nonce, key)?)?;

    let validation = Validation {
        iss: Some(jwt_config.iss.clone()),
        leeway: 60,
        ..Default::default()
    };

    match jsonwebtoken::decode::<Claims>(&jwt, jwt_config.jwt_secret.as_ref(), &validation) {
        Ok(c) => Ok(c.claims.sub),
        Err(err) => {
            match *err.kind() {
                ErrorKind::InvalidToken => error!("Token is invalid"),
                ErrorKind::InvalidIssuer => panic!("Issuer is invalid"),
                _ => panic!("Some other errors"),
            };
            Err(TokenError::InvalidToken)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn token_test() {
        let key = secretbox::gen_key();
        let jwt_config = config::Jwt {
            iss: "test iss".into(),
            jwt_secret: "secret".into(),
            encryption_secret: "secret".into(),
        };

        // run 10 times
        for _ in 0..10 {
            let sub = "test string";
            let token = generate_inner(&jwt_config, &key, &sub, 1000);
            let result = decode_into_sub_inner(&jwt_config, &key, &token);
            assert_eq!(result.unwrap(), sub);
        }
    }
}
