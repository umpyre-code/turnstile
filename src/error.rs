use crate::beancounter_client;
use crate::redis;
use crate::rolodex_client;
use crate::switchroom_client;
use crate::token;

use rocket::response::content;
use rocket_contrib::json::JsonError;

#[derive(Responder, Debug)]
pub enum ResponseError {
    #[response(status = 400, content_type = "json")]
    BadRequest { response: content::Json<String> },
    #[response(status = 401, content_type = "json")]
    Unauthorized { response: content::Json<String> },
    #[response(status = 403, content_type = "json")]
    Forbidden { response: content::Json<String> },
    #[response(status = 404, content_type = "json")]
    NotFound { response: content::Json<String> },
    #[response(status = 401, content_type = "json")]
    PhoneNotVerified { response: content::Json<String> },
}

impl From<std::option::NoneError> for ResponseError {
    fn from(_err: std::option::NoneError) -> Self {
        ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message": "Invalid parameter",
                })
                .to_string(),
            ),
        }
    }
}

impl From<serde_json::error::Error> for ResponseError {
    fn from(err: serde_json::error::Error) -> Self {
        ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message": err.to_string(),
                })
                .to_string(),
            ),
        }
    }
}

impl From<token::TokenError> for ResponseError {
    fn from(err: token::TokenError) -> Self {
        ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message": err.to_string(),
                })
                .to_string(),
            ),
        }
    }
}

impl From<rolodex_client::RolodexError> for ResponseError {
    fn from(err: rolodex_client::RolodexError) -> Self {
        match err {
            rolodex_client::RolodexError::RequestFailure { code, message } => {
                ResponseError::BadRequest {
                    response: content::Json(
                        json!({
                            "code": code as i32,
                            "message": message,
                        })
                        .to_string(),
                    ),
                }
            }
            _ => ResponseError::BadRequest {
                response: content::Json(
                    json!({
                        "message": err.to_string(),
                    })
                    .to_string(),
                ),
            },
        }
    }
}

impl From<switchroom_client::SwitchroomError> for ResponseError {
    fn from(err: switchroom_client::SwitchroomError) -> Self {
        match err {
            switchroom_client::SwitchroomError::RequestFailure { code, message } => {
                ResponseError::BadRequest {
                    response: content::Json(
                        json!({
                            "code": code as i32,
                            "message": message,
                        })
                        .to_string(),
                    ),
                }
            }
            _ => ResponseError::BadRequest {
                response: content::Json(
                    json!({
                        "message": err.to_string(),
                    })
                    .to_string(),
                ),
            },
        }
    }
}

impl From<beancounter_client::BeanCounterError> for ResponseError {
    fn from(err: beancounter_client::BeanCounterError) -> Self {
        match err {
            beancounter_client::BeanCounterError::RequestFailure { code, message } => {
                Self::BadRequest {
                    response: content::Json(
                        json!({
                            "code": code as i32,
                            "message": message,
                        })
                        .to_string(),
                    ),
                }
            }
            _ => Self::BadRequest {
                response: content::Json(
                    json!({
                        "message": err.to_string(),
                    })
                    .to_string(),
                ),
            },
        }
    }
}

impl From<JsonError<'_>> for ResponseError {
    fn from(err: JsonError) -> Self {
        match err {
            JsonError::Io(error) => ResponseError::BadRequest {
                response: content::Json(
                    json!({
                        "message": error.to_string(),
                    })
                    .to_string(),
                ),
            },
            JsonError::Parse(_raw, error) => ResponseError::BadRequest {
                response: content::Json(
                    json!({
                        "message": error.to_string(),
                    })
                    .to_string(),
                ),
            },
        }
    }
}

impl From<&JsonError<'_>> for ResponseError {
    fn from(err: &JsonError) -> Self {
        match err {
            JsonError::Io(error) => ResponseError::BadRequest {
                response: content::Json(
                    json!({
                        "message": error.to_string(),
                    })
                    .to_string(),
                ),
            },
            JsonError::Parse(_raw, error) => ResponseError::BadRequest {
                response: content::Json(
                    json!({
                        "message": error.to_string(),
                    })
                    .to_string(),
                ),
            },
        }
    }
}

impl From<redis::db::RedisError> for ResponseError {
    fn from(err: redis::db::RedisError) -> Self {
        ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message": err.to_string(),
                })
                .to_string(),
            ),
        }
    }
}

impl From<data_encoding::DecodeError> for ResponseError {
    fn from(err: data_encoding::DecodeError) -> Self {
        ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message": err.to_string(),
                })
                .to_string(),
            ),
        }
    }
}

impl From<tera::Error> for ResponseError {
    fn from(err: tera::Error) -> Self {
        ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message": err.to_string(),
                })
                .to_string(),
            ),
        }
    }
}
