use crate::config;
use crate::fairings;
use crate::guards;
use crate::models;
use crate::rolodex_client;
use crate::token;

use rocket::http::{Cookie, Cookies};
use rocket::response::content;
use rocket_contrib::json::Json;

#[derive(Responder, Debug)]
pub enum ResponseError {
    #[response(status = 400, content_type = "json")]
    BadRequest { response: content::Json<String> },
    #[response(status = 403, content_type = "json")]
    Unauthorized { response: content::Json<String> },
}

impl From<rolodex_client::RolodexError> for ResponseError {
    fn from(err: rolodex_client::RolodexError) -> Self {
        ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "error": err.to_string(),
                })
                .to_string(),
            ),
        }
    }
}

#[post("/authenticate", data = "<auth_request>", format = "json")]
pub fn authenticate(
    mut cookies: Cookies,
    redis_writer: fairings::RedisWriter,
    auth_request: Json<models::AuthRequest>,
) -> Result<Json<models::AuthResponse>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);
    let response = rolodex_client.authenticate(rolodex_grpc::proto::AuthRequest {
        user_id: auth_request.user_id.clone(),
        password_hash: auth_request.password_hash.clone(),
    })?;

    match response.result {
        Some(result) => match result {
            rolodex_grpc::proto::auth_response::Result::UserId(user_id) => {
                use rocket_contrib::databases::redis::Commands;

                // generate token (JWT)
                let token = token::generate(&user_id);

                // store token in Redis
                let redis = &*redis_writer;
                let _c: i32 = redis.sadd(&format!("token:{}", user_id), &token).unwrap();

                let cookie = Cookie::build("X-UMPYRE-APIKEY", token.clone())
                    .path("/")
                    .secure(true)
                    .permanent()
                    .finish();
                cookies.add(cookie);

                Ok(Json(models::AuthResponse { user_id, token }))
            }
            rolodex_grpc::proto::auth_response::Result::Error(error) => {
                Err(ResponseError::Unauthorized {
                    response: content::Json(
                        json!({
                            "code": error,
                            "error": "invalid credentials".to_string(),
                        })
                        .to_string(),
                    ),
                })
            }
        },
        None => Err(ResponseError::Unauthorized {
            response: content::Json(
                json!({
                    "error": "invalid credentials".to_string(),
                })
                .to_string(),
            ),
        }),
    }
}

#[derive(Serialize)]
pub struct Hello {
    hi: String,
}

#[get("/hello", format = "json")]
pub fn hello(
    user: guards::User,
    _ratelimited: guards::RateLimitedPrivate,
) -> Result<Json<Hello>, ResponseError> {
    Ok(Json(Hello {
        hi: user.user_id.clone(),
    }))
}

#[get("/ping")]
pub fn ping(_ratelimited: guards::RateLimitedPublic) -> String {
    "pong".into()
}
