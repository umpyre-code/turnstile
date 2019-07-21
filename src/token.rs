extern crate data_encoding;
extern crate jsonwebtoken;

use crate::config;
use jsonwebtoken::{encode, Header, Validation};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    exp: u64,
    iat: u64,
    iss: String,
    jti: String,
    nbf: u64,
    sub: String,
}

pub struct Jwt {
    pub jti: String,
    pub secret: String,
    pub sub: String,
    pub token: String,
}

pub fn generate(sub: &str, expiry: u64) -> Jwt {
    generate_inner(&config::CONFIG.jwt, sub, expiry)
}

fn generate_inner(jwt_config: &config::Jwt, sub: &str, expiry: u64) -> Jwt {
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};
    use std::time::SystemTime;
    use uuid::Uuid;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let jti = Uuid::new_v4().to_simple().to_string();
    let sub = sub.to_string();

    let claims = Claims {
        exp: now + expiry,
        iat: now,
        iss: jwt_config.iss.clone(),
        jti: jti.clone(),
        nbf: now + 300,
        sub: sub.clone(),
    };

    let secret: String = thread_rng().sample_iter(&Alphanumeric).take(50).collect();

    match encode(&Header::default(), &claims, secret.as_bytes()) {
        Ok(token) => Jwt {
            token,
            jti,
            secret,
            sub,
        },
        Err(err) => panic!("error generating jwt: {:?}", err),
    }
}

#[derive(Debug, Fail)]
pub enum TokenError {
    #[fail(display = "failed to decode token: {}", err)]
    DecodingError { err: String },
    #[fail(display = "utf8 decode failure")]
    Utf8Decoding,
}

impl From<data_encoding::DecodeError> for TokenError {
    fn from(err: data_encoding::DecodeError) -> Self {
        TokenError::DecodingError {
            err: err.to_string(),
        }
    }
}

impl From<std::string::FromUtf8Error> for TokenError {
    fn from(_error: std::string::FromUtf8Error) -> Self {
        TokenError::Utf8Decoding
    }
}

impl From<()> for TokenError {
    fn from(_err: ()) -> Self {
        TokenError::DecodingError {
            err: "unknown error".into(),
        }
    }
}

pub fn decode_and_verify(token: &str, secret: &str) -> Result<Jwt, TokenError> {
    decode_and_verify_inner(&config::CONFIG.jwt, token, secret)
}

fn decode_and_verify_inner(
    jwt_config: &config::Jwt,
    token: &str,
    secret: &str,
) -> Result<Jwt, TokenError> {
    let validation = Validation {
        iss: Some(jwt_config.iss.clone()),
        leeway: jwt_config.leeway,
        validate_nbf: true,
        ..Default::default()
    };

    match jsonwebtoken::decode::<Claims>(token, secret.as_bytes(), &validation) {
        Ok(c) => Ok(Jwt {
            jti: c.claims.jti,
            secret: secret.to_string(),
            sub: c.claims.sub,
            token: token.to_string(),
        }),
        Err(err) => Err(TokenError::DecodingError {
            err: err.to_string(),
        }),
    }
}

pub fn decode_sub(token: &str) -> Result<Jwt, TokenError> {
    match jsonwebtoken::dangerous_unsafe_decode::<Claims>(token) {
        Ok(c) => Ok(Jwt {
            jti: c.claims.jti,
            secret: "".to_string(),
            sub: c.claims.sub,
            token: token.to_string(),
        }),
        Err(err) => Err(TokenError::DecodingError {
            err: err.to_string(),
        }),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_token() {
        let jwt_config = config::Jwt {
            iss: "test iss".into(),
            leeway: 300,
        };

        // run 10 times
        for _ in 0..10 {
            let sub = "test string";
            let jwt = generate_inner(&jwt_config, &sub, 1000);
            let result = decode_sub(&jwt.token);
            assert_eq!(result.unwrap().sub, sub);
            let result = decode_and_verify_inner(&jwt_config, &jwt.token, &jwt.secret);
            assert_eq!(result.unwrap().sub, sub);
        }
    }
}
