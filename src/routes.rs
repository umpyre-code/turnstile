use crate::auth;
use crate::config;
use crate::error::ResponseError;
use crate::fairings;
use crate::guards;
use crate::models;
use crate::rolodex_client;
use crate::switchroom_client;
use crate::utils;

use rocket::http::Cookies;
use rocket::response::content;
use rocket_contrib::json::Json;
use rocket_contrib::json::JsonError;

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

    let location = utils::make_location(client_ip, geo_headers);

    let response = rolodex_client.authenticate(rolodex_grpc::proto::AuthRequest {
        client_id: auth_request.client_id.clone(),
        password_hash: auth_request.password_hash.clone(),
        location,
    })?;

    let token = auth::handle_auth_token(cookies, redis_writer, &response.client_id)?;

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

    let location = utils::make_location(client_ip, geo_headers);

    let response = rolodex_client.authenticate(rolodex_grpc::proto::AuthRequest {
        client_id: auth_request.client_id.clone(),
        password_hash: auth_request.password_hash.clone(),
        location,
    })?;

    let token = auth::handle_auth_temporary_token(cookies, redis_writer, &response.client_id)?;

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

    let location = utils::make_location(client_ip, geo_headers);

    let response = rolodex_client.add_client(rolodex_grpc::proto::NewClientRequest {
        full_name: new_client_request.full_name.clone(),
        password_hash: new_client_request.password_hash.clone(),
        email: new_client_request.email.clone(),
        phone_number: Some(rolodex_grpc::proto::PhoneNumber {
            country_code: new_client_request.phone_number.country_code.clone(),
            national_number: new_client_request.phone_number.national_number.clone(),
        }),
        box_public_key: new_client_request.box_public_key.clone(),
        sign_public_key: new_client_request.sign_public_key.clone(),
        location,
    })?;

    let token = auth::handle_auth_token(cookies, redis_writer, &response.client_id)?;

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
            box_public_key: client.box_public_key,
            sign_public_key: client.sign_public_key,
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
            box_public_key: client.box_public_key,
            sign_public_key: client.sign_public_key,
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

    let location = utils::make_location(client_ip, geo_headers);

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
            box_public_key: update_client_request.box_public_key.clone(),
            sign_public_key: update_client_request.sign_public_key.clone(),
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
        let sent_at = message.sent_at.as_ref().unwrap();
        models::Message {
            to: message.to.clone(),
            from: message.from.clone(),
            body: BASE64_NOPAD.encode(&message.body),
            hash: Some(BASE64_NOPAD.encode(&message.hash)),
            received_at: Some(models::Timestamp {
                seconds: received_at.seconds,
                nanos: received_at.nanos,
            }),
            nonce: BASE64_NOPAD.encode(&message.nonce),
            sender_public_key: BASE64_NOPAD.encode(&message.sender_public_key),
            recipient_public_key: BASE64_NOPAD.encode(&message.recipient_public_key),
            pda: message.pda.clone(),
            sent_at: models::Timestamp {
                seconds: sent_at.seconds,
                nanos: sent_at.nanos,
            },
            signature: Some(BASE64_NOPAD.encode(&message.signature)),
        }
    }
}

impl From<switchroom_grpc::proto::Message> for models::Message {
    fn from(message: switchroom_grpc::proto::Message) -> Self {
        models::Message::from(&message)
    }
}

fn check_box_public_keys(
    rolodex_client: &rolodex_client::Client,
    calling_client_id: &str,
    client_id: &str,
    expected_box_public_key: &str,
) -> Result<rolodex_grpc::proto::Client, ResponseError> {
    let response = rolodex_client.get_client(rolodex_grpc::proto::GetClientRequest {
        client_id: client_id.into(),
        calling_client_id: calling_client_id.into(),
    })?;

    let client = response.client?;
    if expected_box_public_key.eq(&client.box_public_key) {
        Ok(client)
    } else {
        Err(ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message:": "Invalid box public key (didn't match the one on record)",
                    "expected": expected_box_public_key,
                    "found": client.box_public_key
                })
                .to_string(),
            ),
        })
    }
}

fn check_message_signature(
    client: &rolodex_grpc::proto::Client,
    message: &models::Message,
) -> Result<(), ResponseError> {
    use data_encoding::BASE64_NOPAD;
    use sodiumoxide::crypto::sign;

    let pk = sign::PublicKey::from_slice(&BASE64_NOPAD.decode(client.sign_public_key.as_bytes())?)?;

    let signature =
        sign::Signature::from_slice(&BASE64_NOPAD.decode(message.signature.as_ref()?.as_bytes())?)?;

    let message_json = serde_json::to_string(&models::Message {
        signature: None,
        ..message.clone()
    })?;

    if sign::verify_detached(&signature, &message_json.as_bytes(), &pk) {
        Ok(())
    } else {
        Err(ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message:": "Invalid message signature",
                    "sign_public_key": client.sign_public_key,
                })
                .to_string(),
            ),
        })
    }
}

fn check_message_hash(message: &models::Message) -> Result<(), ResponseError> {
    use data_encoding::BASE64_NOPAD;
    use sodiumoxide::crypto::generichash;

    let mut hasher = generichash::State::new(16, None).unwrap();

    let message_json = serde_json::to_string(&models::Message {
        signature: None,
        hash: None,
        ..message.clone()
    })?;
    println!("{}", message_json);

    hasher.update(message_json.as_bytes()).unwrap();
    let digest = hasher.finalize().unwrap();
    let expected_hash = BASE64_NOPAD.encode(digest.as_ref());
    let empty_string = String::from("");
    let hash = message.hash.as_ref().unwrap_or(&empty_string);

    if expected_hash.eq(hash) {
        Ok(())
    } else {
        Err(ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message:": "Invalid message hash",
                    "expected": expected_hash,
                    "found": message.hash,
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

    // Verify the message hash
    check_message_hash(&message)?;

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    // Verify the public key of the client sending this message matches what's
    // in our DB. Keep the client struct so we can verify the signature as well.
    let sending_client = check_box_public_keys(
        &rolodex_client,
        &calling_client.client_id,
        &calling_client.client_id,
        &message.sender_public_key,
    )?;

    // Verify the public key of the recipient matches what's in our DB
    check_box_public_keys(
        &rolodex_client,
        &calling_client.client_id,
        &message.to,
        &message.recipient_public_key,
    )?;

    // Verify the message signature
    check_message_signature(&sending_client, &message)?;

    let switchroom_client = switchroom_client::Client::new(&config::CONFIG);

    let response = switchroom_client.send_message(switchroom_grpc::proto::Message {
        to: message.to.clone(),
        body: BASE64_NOPAD.decode(message.body.as_bytes())?,
        from: calling_client.client_id.clone(),
        hash: BASE64_NOPAD.decode(message.hash.as_ref()?.as_bytes())?,
        received_at: None,
        nonce: BASE64_NOPAD.decode(message.nonce.as_bytes())?,
        sender_public_key: BASE64_NOPAD.decode(message.sender_public_key.as_bytes())?,
        recipient_public_key: BASE64_NOPAD.decode(message.recipient_public_key.as_bytes())?,
        pda: message.pda.clone(),
        sent_at: Some(switchroom_grpc::proto::Timestamp {
            seconds: message.sent_at.seconds,
            nanos: message.sent_at.nanos,
        }),
        signature: BASE64_NOPAD.decode(message.signature.as_ref()?.as_bytes())?,
    })?;

    Ok(Json(response.into()))
}
