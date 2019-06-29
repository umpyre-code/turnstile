use crate::config;
use crate::fairings;
use crate::guards;
use crate::models;
use crate::rolodex_client;
use crate::switchroom_client;
use crate::token;

use rocket::http::{Cookie, Cookies};
use rocket::response::content;
use rocket_contrib::json::Json;
use rocket_contrib::json::JsonError;

#[derive(Responder, Debug)]
pub enum ResponseError {
    #[response(status = 400, content_type = "json")]
    BadRequest { response: content::Json<String> },
    #[response(status = 401, content_type = "json")]
    Forbidden { response: content::Json<String> },
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
                        "message:": err.to_string(),
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

impl From<data_encoding::DecodeError> for ResponseError {
    fn from(err: data_encoding::DecodeError) -> Self {
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
    auth_request: Result<Json<models::AuthRequest>, JsonError>,
) -> Result<Json<models::AuthResponse>, ResponseError> {
    let auth_request = match auth_request {
        Ok(auth_request) => auth_request,
        Err(err) => return Err(err.into()),
    };

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
    auth_request: Result<Json<models::AuthRequest>, JsonError>,
) -> Result<Json<models::AuthResponse>, ResponseError> {
    let auth_request = match auth_request {
        Ok(auth_request) => auth_request,
        Err(err) => return Err(err.into()),
    };

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
    new_client_request: Result<Json<models::NewClientRequest>, JsonError>,
) -> Result<Json<models::NewClientResponse>, ResponseError> {
    let new_client_request = match new_client_request {
        Ok(new_client_request) => new_client_request,
        Err(err) => return Err(err.into()),
    };

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

impl From<rolodex_grpc::proto::UpdateClientResponse> for models::UpdateClientResponse {
    fn from(response: rolodex_grpc::proto::UpdateClientResponse) -> Self {
        let client = response.client.unwrap();
        models::UpdateClientResponse {
            client_id: client.client_id,
            full_name: client.full_name,
            public_key: client.public_key,
        }
    }
}

fn check_result(result: i32) -> Result<(), ResponseError> {
    if result != rolodex_grpc::proto::Result::Success as i32 {
        Err(ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message:": "Update request failed",
                })
                .to_string(),
            ),
        })
    } else {
        Ok(())
    }
}

#[put(
    "/client/<client_id>",
    data = "<update_client_request>",
    format = "json"
)]
pub fn put_client(
    client_id: String,
    calling_client: guards::Client,
    temp_client: Option<guards::TempClient>,
    _ratelimited: guards::RateLimitedPrivate,
    update_client_request: Result<Json<models::UpdateClientRequest>, JsonError>,
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
) -> Result<Json<models::UpdateClientResponse>, ResponseError> {
    let update_client_request = match update_client_request {
        Ok(update_client_request) => update_client_request,
        Err(err) => return Err(err.into()),
    };

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    if client_id != calling_client.client_id {
        return Err(ResponseError::Forbidden {
            response: content::Json(
                json!({
                    "message:": "Not authorized to modify the specified client account",
                })
                .to_string(),
            ),
        });
    }

    let location = make_location(client_ip, geo_headers);

    if update_client_request.password_hash.is_some()
        || update_client_request.email.is_some()
        || update_client_request.phone_number.is_some()
    {
        // Trying to update password, email, or phone number, so we must have a
        // temporary auth token
        if temp_client.is_none() {
            return Err(ResponseError::Forbidden {
                response: content::Json(
                    json!({
                        "message:": "Not authorized to modify the specified client account",
                    })
                    .to_string(),
                ),
            });
        }

        if let Some(password_hash) = &update_client_request.password_hash {
            // Update password hash
            let response = rolodex_client.update_client_password(
                rolodex_grpc::proto::UpdateClientPasswordRequest {
                    client_id: client_id.clone(),
                    password_hash: password_hash.clone(),
                    location: location.clone(),
                },
            )?;

            check_result(response.result)?;
        }

        if let Some(email) = &update_client_request.email {
            // Update email
            let response = rolodex_client.update_client_email(
                rolodex_grpc::proto::UpdateClientEmailRequest {
                    client_id: client_id.clone(),
                    email: email.clone(),
                    location: location.clone(),
                },
            )?;

            check_result(response.result)?;
        }

        if let Some(phone_number) = &update_client_request.phone_number {
            // Update phone number
            let response = rolodex_client.update_client_phone_number(
                rolodex_grpc::proto::UpdateClientPhoneNumberRequest {
                    client_id: client_id.clone(),
                    phone_number: Some(rolodex_grpc::proto::PhoneNumber {
                        country_code: phone_number.country_code.clone(),
                        national_number: phone_number.national_number.clone(),
                    }),
                    location: location.clone(),
                },
            )?;

            check_result(response.result)?;
        }
    }

    let response = rolodex_client.update_client(rolodex_grpc::proto::UpdateClientRequest {
        client: Some(rolodex_grpc::proto::Client {
            client_id,
            full_name: update_client_request.full_name.clone(),
            public_key: update_client_request.public_key.clone(),
        }),
        location,
    })?;

    check_result(response.result)?;

    Ok(Json(response.into()))
}

#[get("/ping")]
pub fn get_ping(_ratelimited: guards::RateLimitedPublic) -> String {
    "pong".into()
}

impl From<switchroom_grpc::proto::GetMessagesResponse> for models::GetMessagesResponse {
    fn from(response: switchroom_grpc::proto::GetMessagesResponse) -> Self {
        models::GetMessagesResponse {
            messages: response
                .messages
                .iter()
                .map(models::Message::from)
                .collect(),
        }
    }
}

#[get("/messages")]
pub fn get_messages(
    calling_client: guards::Client,
    _ratelimited: guards::RateLimitedPrivate,
) -> Result<Json<models::GetMessagesResponse>, ResponseError> {
    let switchroom_client = switchroom_client::Client::new(&config::CONFIG);

    let response = switchroom_client.get_messages(switchroom_grpc::proto::GetMessagesRequest {
        client_id: calling_client.client_id,
        sketch: "".into(),
    })?;

    Ok(Json(response.into()))
}

impl From<&switchroom_grpc::proto::Message> for models::Message {
    fn from(message: &switchroom_grpc::proto::Message) -> Self {
        use data_encoding::BASE64_NOPAD;
        let received_at = message.received_at.as_ref().unwrap();
        models::Message {
            to: message.to.clone(),
            from: message.from.clone(),
            body: BASE64_NOPAD.encode(&message.body),
            hash: BASE64_NOPAD.encode(&message.hash),
            received_at: models::Timestamp {
                seconds: received_at.seconds,
                nanos: received_at.nanos,
            },
            nonce: BASE64_NOPAD.encode(&message.nonce),
            sender_public_key: BASE64_NOPAD.encode(&message.sender_public_key),
            recipient_public_key: BASE64_NOPAD.encode(&message.recipient_public_key),
            pda: message.pda.clone(),
        }
    }
}

impl From<switchroom_grpc::proto::Message> for models::Message {
    fn from(message: switchroom_grpc::proto::Message) -> Self {
        models::Message::from(&message)
    }
}

fn check_public_keys(
    rolodex_client: &rolodex_client::Client,
    calling_client_id: &str,
    client_id: &str,
    expected_public_key: &str,
) -> Result<(), ResponseError> {
    let response = rolodex_client.get_client(rolodex_grpc::proto::GetClientRequest {
        client_id: client_id.into(),
        calling_client_id: calling_client_id.into(),
    })?;

    let client = response.client.unwrap();
    if expected_public_key.eq(&client.public_key) {
        Ok(())
    } else {
        Err(ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message:": "Invalid public key (didn't match the one on record)",
                    "expected": expected_public_key,
                    "found": client.public_key
                })
                .to_string(),
            ),
        })
    }
}

#[post("/messages", data = "<message>", format = "json")]
pub fn post_message(
    message: Result<Json<models::Message>, JsonError>,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimitedPrivate,
) -> Result<Json<models::Message>, ResponseError> {
    use data_encoding::BASE64_NOPAD;

    let message = match message {
        Ok(message) => message,
        Err(err) => return Err(err.into()),
    };

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    // Verify the public key of the client sending this message matches what's
    // in our DB
    check_public_keys(
        &rolodex_client,
        &calling_client.client_id,
        &calling_client.client_id,
        &message.sender_public_key,
    )?;

    // Verify the public key of the recipient matches what's in our DB
    check_public_keys(
        &rolodex_client,
        &calling_client.client_id,
        &message.to,
        &message.recipient_public_key,
    )?;

    let switchroom_client = switchroom_client::Client::new(&config::CONFIG);

    let response = switchroom_client.send_message(switchroom_grpc::proto::Message {
        to: message.to.clone(),
        body: BASE64_NOPAD.decode(message.body.as_bytes())?,
        from: calling_client.client_id.clone(),
        hash: "".into(),
        received_at: None,
        nonce: BASE64_NOPAD.decode(message.nonce.as_bytes())?,
        sender_public_key: BASE64_NOPAD.decode(message.sender_public_key.as_bytes())?,
        recipient_public_key: BASE64_NOPAD.decode(message.recipient_public_key.as_bytes())?,
        pda: message.pda.clone(),
    })?;

    Ok(Json(response.into()))
}
