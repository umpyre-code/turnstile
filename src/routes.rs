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

fn make_location(
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
) -> Option<rolodex_grpc::proto::Location> {
    if let Some(location) = geo_headers {
        Some(rolodex_grpc::proto::Location {
            ip_address: client_ip.0,
            region: location.region,
            region_subdivision: location.region_subdivision,
            city: location.city,
        })
    } else {
        Some(rolodex_grpc::proto::Location {
            ip_address: client_ip.0,
            region: "unknown".into(),
            region_subdivision: "unknown".into(),
            city: "unknown".into(),
        })
    }
}

fn handle_auth_token(
    mut cookies: Cookies,
    redis_writer: fairings::RedisWriter,
    client_id: &str,
) -> Result<String, ResponseError> {
    use rocket_contrib::databases::redis::Commands;
    use time::Duration;

    // 1 year expiry
    let expiry = 365 * 24 * 3600;

    // generate token (JWT)
    let token = token::generate(&client_id, expiry);

    // store token in Redis
    let redis = &*redis_writer;
    let _c: i32 = redis.sadd(&format!("token:{}", client_id), &token)?;

    let cookie = Cookie::build("X-UMPYRE-APIKEY", token.clone())
        .path("/")
        .secure(true)
        .max_age(Duration::seconds(expiry as i64))
        .finish();
    cookies.add(cookie);

    Ok(token)
}

fn handle_auth_temporary_token(
    mut cookies: Cookies,
    redis_writer: fairings::RedisWriter,
    client_id: &str,
) -> Result<String, ResponseError> {
    use rocket_contrib::databases::redis::Commands;
    use time::Duration;

    // 1 hour expiry
    let expiry = 3600;

    // generate token (JWT)
    let token = token::generate(&client_id, expiry);

    // store token in Redis
    let redis = &*redis_writer;
    let _c: i32 = redis.sadd(&format!("token:{}", client_id), &token)?;

    let cookie = Cookie::build("X-UMPYRE-APIKEY-TEMP", token.clone())
        .path("/")
        .secure(true)
        .max_age(Duration::seconds(expiry as i64))
        .finish();
    cookies.add(cookie);

    Ok(token)
}

#[post("/client/authenticate", data = "<auth_request>", format = "json")]
pub fn post_client_authenticate(
    _ratelimited: guards::RateLimitedPublic,
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    cookies: Cookies,
    redis_writer: fairings::RedisWriter,
    auth_request: Json<models::AuthRequest>,
) -> Result<Json<models::AuthResponse>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let location = make_location(client_ip, geo_headers);

    let response = rolodex_client.authenticate(rolodex_grpc::proto::AuthRequest {
        client_id: auth_request.client_id.clone(),
        password_hash: auth_request.password_hash.clone(),
        location,
    })?;

    let token = handle_auth_token(cookies, redis_writer, &response.client_id)?;

    Ok(Json(models::AuthResponse {
        client_id: response.client_id,
        token,
    }))
}

#[post(
    "/client/authenticate-temporarily",
    data = "<auth_request>",
    format = "json"
)]
pub fn post_client_authenticate_temporarily(
    _ratelimited: guards::RateLimitedPublic,
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    cookies: Cookies,
    redis_writer: fairings::RedisWriter,
    auth_request: Json<models::AuthRequest>,
) -> Result<Json<models::AuthResponse>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let location = make_location(client_ip, geo_headers);

    let response = rolodex_client.authenticate(rolodex_grpc::proto::AuthRequest {
        client_id: auth_request.client_id.clone(),
        password_hash: auth_request.password_hash.clone(),
        location,
    })?;

    let token = handle_auth_temporary_token(cookies, redis_writer, &response.client_id)?;

    Ok(Json(models::AuthResponse {
        client_id: response.client_id,
        token,
    }))
}

#[post("/client", data = "<new_client_request>", format = "json")]
pub fn post_client(
    _ratelimited: guards::RateLimitedPublic,
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    cookies: Cookies,
    redis_writer: fairings::RedisWriter,
    new_client_request: Json<models::NewClientRequest>,
) -> Result<Json<models::NewClientResponse>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let location = make_location(client_ip, geo_headers);

    let response = rolodex_client.add_client(rolodex_grpc::proto::NewClientRequest {
        full_name: new_client_request.full_name.clone(),
        password_hash: new_client_request.password_hash.clone(),
        email: new_client_request.email.clone(),
        phone_number: Some(rolodex_grpc::proto::PhoneNumber {
            country_code: new_client_request.phone_number.country_code.clone(),
            national_number: new_client_request.phone_number.national_number.clone(),
        }),
        public_key: new_client_request.public_key.clone(),
        location,
    })?;

    let token = handle_auth_token(cookies, redis_writer, &response.client_id)?;

    Ok(Json(models::NewClientResponse {
        client_id: response.client_id,
        token,
    }))
}

impl From<rolodex_grpc::proto::GetClientResponse> for models::GetClientResponse {
    fn from(response: rolodex_grpc::proto::GetClientResponse) -> Self {
        let client = response.client.unwrap();
        models::GetClientResponse {
            client_id: client.client_id,
            full_name: client.full_name,
            public_key: client.public_key,
        }
    }
}

#[get("/client/<client_id>")]
pub fn get_client(
    client_id: String,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimitedPrivate,
) -> Result<Json<models::GetClientResponse>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let response = rolodex_client.get_client(rolodex_grpc::proto::GetClientRequest {
        client_id,
        calling_client_id: calling_client.client_id,
    })?;

    Ok(Json(response.into()))
}

#[put("/client/<client_id>")]
pub fn put_client(
    client_id: String,
    calling_client: guards::Client,
    temp_client: Option<guards::TempClient>,
    _ratelimited: guards::RateLimitedPrivate,
) -> Result<Json<models::GetClientResponse>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let response = rolodex_client.get_client(rolodex_grpc::proto::GetClientRequest {
        client_id,
        calling_client_id: calling_client.client_id,
    })?;

    Ok(Json(response.into()))
}

#[get("/ping")]
pub fn get_ping(_ratelimited: guards::RateLimitedPublic) -> String {
    "pong".into()
}
