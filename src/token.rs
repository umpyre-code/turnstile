extern crate data_encoding;
extern crate jsonwebtoken;

use crate::config;
use data_encoding::HEXLOWER;
use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::{encode, Header, Validation};
use sodiumoxide::crypto::secretbox;
use sodiumoxide::crypto::secretbox::xsalsa20poly1305::{Key, Nonce};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
    exp: usize,
}

lazy_static! {
    static ref SECRET_KEY: Key = {
        Key::from_slice(
            &HEXLOWER
                .decode(config::CONFIG.jwt.encryption_secret.as_bytes())
                .unwrap(),
        )
        .unwrap()
    };
}

pub fn generate(user_id: &str) -> String {
    let claims = Claims {
        sub: user_id.to_string(),
        iss: config::CONFIG.jwt.iss.clone(),
        exp: config::CONFIG.jwt.exp,
    };

    match encode(
        &Header::default(),
        &claims,
        config::CONFIG.jwt.jwt_secret.as_ref(),
    ) {
        Ok(token) => {
            let nonce = secretbox::gen_nonce();
            let ciphertext = secretbox::seal(token.as_bytes(), &nonce, &SECRET_KEY);
            // Nonce is first 24 bytes, or 48 chars
            // Remaining bytes are ciphertext.
            format!(
                "{}{}",
                HEXLOWER.encode(nonce.as_ref()).to_string(),
                HEXLOWER.encode(&ciphertext).to_string(),
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
}

impl From<data_encoding::DecodeError> for TokenError {
    fn from(_error: data_encoding::DecodeError) -> Self {
        TokenError::DecodingError
    }
}

impl From<std::string::FromUtf8Error> for TokenError {
    fn from(_error: std::string::FromUtf8Error) -> Self {
        TokenError::DecodingError
    }
}

impl From<()> for TokenError {
    fn from(_error: ()) -> Self {
        TokenError::DecodingError
    }
}


pub fn decode_into_user_id(token: &str) -> Result<String, TokenError> {
    let ciphertext = HEXLOWER.decode(token[48..].as_bytes())?;
    let nonce = Nonce::from_slice(&HEXLOWER.decode(token[..48].as_bytes())?).unwrap();
    let jwt = String::from_utf8(secretbox::open(&ciphertext, &nonce, &SECRET_KEY)?)?;

    let validation = Validation {
        iss: Some(config::CONFIG.jwt.iss.clone()),
        leeway: 60,
        ..Default::default()
    };

    match jsonwebtoken::decode::<Claims>(&jwt, config::CONFIG.jwt.jwt_secret.as_ref(), &validation)
    {
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
