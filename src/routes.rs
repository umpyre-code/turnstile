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
    #[response(status = 503, content_type = "json")]
    DatabaseError { response: content::Json<String> },
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
                        "message:": err.to_string(),
                    })
                    .to_string(),
                ),
            },
        }
    }
}

impl From<rocket_contrib::databases::redis::RedisError> for ResponseError {
    fn from(err: rocket_contrib::databases::redis::RedisError) -> Self {
        ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message:": err.to_string(),
                })
                .to_string(),
            ),
        }
    }
}

fn handle_auth_token(
    mut cookies: Cookies,
    redis_writer: fairings::RedisWriter,
    user_id: &str,
) -> Result<String, ResponseError> {
    use rocket_contrib::databases::redis::Commands;

    // generate token (JWT)
    let token = token::generate(&user_id);

    // store token in Redis
    let redis = &*redis_writer;
    let _c: i32 = redis.sadd(&format!("token:{}", user_id), &token)?;

    let cookie = Cookie::build("X-UMPYRE-APIKEY", token.clone())
        .path("/")
        .secure(true)
        .permanent()
        .finish();
    cookies.add(cookie);

    Ok(token)
}

#[post("/user/authenticate", data = "<auth_request>", format = "json")]
pub fn post_user_authenticate(
    _ratelimited: guards::RateLimitedPublic,
    cookies: Cookies,
    redis_writer: fairings::RedisWriter,
    auth_request: Json<models::AuthRequest>,
) -> Result<Json<models::AuthResponse>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);
    let response = rolodex_client.authenticate(rolodex_grpc::proto::AuthRequest {
        user_id: auth_request.user_id.clone(),
        password_hash: auth_request.password_hash.clone(),
    })?;

    let token = handle_auth_token(cookies, redis_writer, &response.user_id)?;

    Ok(Json(models::AuthResponse {
        user_id: response.user_id,
        token,
    }))
}

#[post("/user", data = "<new_user_request>", format = "json")]
pub fn post_user(
    _ratelimited: guards::RateLimitedPublic,
    cookies: Cookies,
    redis_writer: fairings::RedisWriter,
    new_user_request: Json<models::NewUserRequest>,
) -> Result<Json<models::NewUserResponse>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let response = rolodex_client.add_user(rolodex_grpc::proto::NewUserRequest {
        full_name: new_user_request.full_name.clone(),
        password_hash: new_user_request.password_hash.clone(),
        email: new_user_request.email.clone(),
        phone_number: Some(rolodex_grpc::proto::PhoneNumber {
            country: new_user_request.phone_number.country.clone(),
            number: new_user_request.phone_number.number.clone(),
        }),
        public_key: new_user_request.public_key.clone(),
    })?;

    let token = handle_auth_token(cookies, redis_writer, &response.user_id)?;

    Ok(Json(models::NewUserResponse {
        user_id: response.user_id,
        token,
    }))
}

impl From<rolodex_grpc::proto::GetUserResponse> for models::GetUserResponse {
    fn from(response: rolodex_grpc::proto::GetUserResponse) -> Self {
        models::GetUserResponse {
            user_id: response.user_id,
            full_name: response.full_name,
            public_key: response.public_key,
        }
    }
}

#[get("/user/<user_id>")]
pub fn get_user(
    user_id: String,
    calling_user: guards::User,
    _ratelimited: guards::RateLimitedPrivate,
) -> Result<Json<models::GetUserResponse>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let response = rolodex_client.get_user(rolodex_grpc::proto::GetUserRequest {
        user_id,
        calling_user_id: calling_user.user_id,
    })?;

    Ok(Json(response.into()))
}

#[get("/ping")]
pub fn get_ping(_ratelimited: guards::RateLimitedPublic) -> String {
    "pong".into()
}
