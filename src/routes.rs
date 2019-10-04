use crate::auth;
use crate::beancounter_client;
use crate::config;
use crate::elasticsearch;
use crate::error::ResponseError;
use crate::fairings;
use crate::gcp;
use crate::guards;
use crate::mailgun;
use crate::message;
use crate::models;
use crate::responders::Cached;
use crate::rolodex_client;
use crate::switchroom_client;
use crate::utils;

use rocket::response::content;
use rocket_contrib::json::Json;
use rocket_contrib::json::JsonError;

fn handle_auth_handshake(
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    auth_request: &Result<Json<models::AuthHandshakeRequest>, JsonError>,
) -> Result<Json<models::AuthHandshakeResponse>, ResponseError> {
    use data_encoding::BASE64URL_NOPAD;

    let auth_request = match auth_request {
        Ok(auth_request) => auth_request,
        Err(err) => return Err(err.into()),
    };

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let location = utils::make_location(client_ip, geo_headers);

    let response = rolodex_client.auth_handshake(rolodex_grpc::proto::AuthHandshakeRequest {
        email: auth_request.email.clone(),
        a_pub: BASE64URL_NOPAD
            .decode(auth_request.a_pub.as_bytes())?
            .to_vec(),
        location,
    })?;

    Ok(Json(models::AuthHandshakeResponse {
        salt: BASE64URL_NOPAD.encode(&response.salt),
        b_pub: BASE64URL_NOPAD.encode(&response.b_pub),
    }))
}

fn handle_auth_verify(
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    auth_request: &Result<Json<models::AuthVerifyRequest>, JsonError>,
) -> Result<rolodex_grpc::proto::AuthVerifyResponse, ResponseError> {
    use data_encoding::BASE64URL_NOPAD;

    let auth_request = match auth_request {
        Ok(auth_request) => auth_request,
        Err(err) => return Err(err.into()),
    };

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let location = utils::make_location(client_ip, geo_headers);

    let response = rolodex_client.auth_verify(rolodex_grpc::proto::AuthVerifyRequest {
        email: auth_request.email.clone(),
        a_pub: BASE64URL_NOPAD
            .decode(auth_request.a_pub.as_bytes())?
            .to_vec(),
        client_proof: BASE64URL_NOPAD
            .decode(auth_request.client_proof.as_bytes())?
            .to_vec(),
        location,
    })?;

    Ok(response)
}

#[post("/client/auth/handshake", data = "<auth_request>", format = "json")]
pub fn post_client_auth_handshake(
    _ratelimited: guards::RateLimited,
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    _redis_writer: fairings::RedisWriter,
    auth_request: Result<Json<models::AuthHandshakeRequest>, JsonError>,
) -> Result<Json<models::AuthHandshakeResponse>, ResponseError> {
    handle_auth_handshake(client_ip, geo_headers, &auth_request)
}

#[post("/client/auth/verify", data = "<auth_request>", format = "json")]
pub fn post_client_auth_verify(
    _ratelimited: guards::RateLimited,
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    mut redis_writer: fairings::RedisWriter,
    auth_request: Result<Json<models::AuthVerifyRequest>, JsonError>,
) -> Result<Json<models::AuthVerifyResponse>, ResponseError> {
    use data_encoding::BASE64URL_NOPAD;

    let response = handle_auth_verify(client_ip, geo_headers, &auth_request)?;

    let jwt = auth::generate_auth_token(
        &mut *redis_writer,
        &response.client_id,
        &response.session_key,
    )?;

    Ok(Json(models::AuthVerifyResponse {
        client_id: response.client_id,
        server_proof: BASE64URL_NOPAD.encode(&response.server_proof),
        jwt,
    }))
}

#[post(
    "/client/auth-temporarily/handshake",
    data = "<auth_request>",
    format = "json"
)]
pub fn post_client_auth_handshake_temporarily(
    _ratelimited: guards::RateLimited,
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    auth_request: Result<Json<models::AuthHandshakeRequest>, JsonError>,
) -> Result<Json<models::AuthHandshakeResponse>, ResponseError> {
    handle_auth_handshake(client_ip, geo_headers, &auth_request)
}

#[post(
    "/client/auth-temporarily/verify",
    data = "<auth_request>",
    format = "json"
)]
pub fn post_client_auth_verify_temporarily(
    _ratelimited: guards::RateLimited,
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    mut redis_writer: fairings::RedisWriter,
    auth_request: Result<Json<models::AuthVerifyRequest>, JsonError>,
) -> Result<Json<models::AuthVerifyResponse>, ResponseError> {
    use data_encoding::BASE64URL_NOPAD;

    let response = handle_auth_verify(client_ip, geo_headers, &auth_request)?;

    let jwt = auth::generate_auth_temporary_token(
        &mut *redis_writer,
        &response.client_id,
        &response.session_key,
    )?;

    Ok(Json(models::AuthVerifyResponse {
        client_id: response.client_id,
        server_proof: BASE64URL_NOPAD.encode(&response.server_proof),
        jwt,
    }))
}

#[post("/client", data = "<new_client_request>", format = "json")]
pub fn post_client(
    _ratelimited: guards::RateLimited,
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    new_client_request: Result<Json<models::NewClientRequest>, JsonError>,
) -> Result<Json<models::NewClientResponse>, ResponseError> {
    use data_encoding::BASE64URL_NOPAD;

    let new_client_request = match new_client_request {
        Ok(new_client_request) => new_client_request,
        Err(err) => return Err(err.into()),
    };

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let location = utils::make_location(client_ip, geo_headers);

    let response = rolodex_client.add_client(rolodex_grpc::proto::NewClientRequest {
        full_name: new_client_request.full_name.clone(),
        password_verifier: BASE64URL_NOPAD
            .decode(new_client_request.password_verifier.as_bytes())?
            .to_vec(),
        password_salt: BASE64URL_NOPAD
            .decode(new_client_request.password_salt.as_bytes())?
            .to_vec(),
        email: new_client_request.email.clone(),
        phone_number: Some(rolodex_grpc::proto::PhoneNumber {
            country_code: new_client_request.phone_number.country_code.clone(),
            national_number: new_client_request.phone_number.national_number.clone(),
        }),
        box_public_key: new_client_request.box_public_key.clone(),
        signing_public_key: new_client_request.signing_public_key.clone(),
        location,
        referred_by: new_client_request.referred_by.clone(),
    })?;

    // Update the index in elasticsearch. This is launched on a separate thread
    // so it doesn't block.
    let elastic_doc = elasticsearch::ClientProfileDocument::new(
        &response.client_id,
        &new_client_request.full_name,
        "",
        0,
    );
    let to_client_id = response.client_id.clone();
    let to_public_key = new_client_request.box_public_key.clone();
    let to_full_name = new_client_request.full_name.clone();
    std::thread::spawn(move || {
        let elastic = elasticsearch::ElasticSearchClient::new();
        elastic.update(elastic_doc);
        // deliver welcome message
        let vec: Vec<String> = to_full_name
            .split_whitespace()
            .map(|s| s.to_string())
            .collect();
        let to_first_name = vec.first().unwrap();
        let _welcome_message =
            match message::create_welcome_message(&to_client_id, &to_public_key, to_first_name) {
                Ok(welcome_message) => welcome_message,
                Err(err) => error!("error generating welcome message: {:?}", err),
            };
    });

    Ok(Json(models::NewClientResponse {
        client_id: response.client_id,
    }))
}

impl From<rolodex_grpc::proto::Client> for models::GetClientResponse {
    fn from(client: rolodex_grpc::proto::Client) -> Self {
        use crate::optional::Optional;
        models::GetClientResponse {
            client_id: client.client_id,
            full_name: client.full_name,
            box_public_key: client.box_public_key,
            signing_public_key: client.signing_public_key,
            handle: client.handle.into_option(),
            profile: client.profile.into_option(),
            joined: client.joined,
            phone_sms_verified: client.phone_sms_verified,
            ral: client.ral,
            avatar_version: client.avatar_version,
        }
    }
}

impl From<Option<rolodex_grpc::proto::Client>> for models::GetClientResponse {
    fn from(client: Option<rolodex_grpc::proto::Client>) -> Self {
        let client = client.unwrap();
        client.into()
    }
}

impl From<rolodex_grpc::proto::GetClientResponse> for models::GetClientResponse {
    fn from(response: rolodex_grpc::proto::GetClientResponse) -> Self {
        response.client.into()
    }
}

#[get("/client/<arg_client_id>")]
pub fn get_client(
    arg_client_id: String,
    calling_client: Option<guards::Client>,
    _ratelimited: guards::RateLimited,
    mut redis_writer: fairings::RedisWriter,
) -> Result<Cached<Json<models::GetClientResponse>>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let fetch_client_id = if arg_client_id == "self" {
        if calling_client.is_none() {
            return Err(ResponseError::Unauthorized {
                response: content::Json(
                    json!({
                        "message:": "Authentication required",
                    })
                    .to_string(),
                ),
            });
        } else {
            calling_client.as_ref().unwrap().client_id.clone()
        }
    } else {
        arg_client_id.clone()
    };

    let response = rolodex_client.get_client(rolodex_grpc::proto::GetClientRequest {
        id: Some(rolodex_grpc::proto::get_client_request::Id::ClientId(
            fetch_client_id.clone(),
        )),
        calling_client_id: match calling_client.as_ref() {
            Some(client) => client.client_id.clone(),
            _ => "".to_string(),
        },
    });

    if response.is_ok() {
        // if this is the magic '/client/self' endpoint, don't cache it
        let cache_seconds = if arg_client_id == "self" {
            0
        } else {
            60 * 60 // 1h
        };
        Ok(Cached::from(Json(response.unwrap().into()), cache_seconds))
    } else if calling_client.is_some() && calling_client.unwrap().client_id == fetch_client_id {
        // If the calling client credentials are valid, but this client doesn't
        // exist anymore, that means it was removed from the backend. Delete
        // tokens from redis and return 403.
        auth::delete_tokens_for(&mut redis_writer, &fetch_client_id)?;
        Err(ResponseError::Unauthorized {
            response: content::Json(
                json!({
                    "message:": "Client no longer valid",
                })
                .to_string(),
            ),
        })
    } else {
        Err(ResponseError::NotFound {
            response: content::Json(
                json!({
                    "message:": "Client not found",
                    "client_id": arg_client_id
                })
                .to_string(),
            ),
        })
    }
}

#[get("/handle/<handle>")]
pub fn get_client_by_handle(
    handle: String,
    calling_client: Option<guards::Client>,
    _ratelimited: guards::RateLimited,
) -> Result<Cached<Json<models::GetClientResponse>>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let response = rolodex_client.get_client(rolodex_grpc::proto::GetClientRequest {
        id: Some(rolodex_grpc::proto::get_client_request::Id::Handle(
            handle.clone(),
        )),
        calling_client_id: match calling_client {
            Some(client) => client.client_id,
            _ => "".to_string(),
        },
    });

    if response.is_ok() {
        Ok(Cached::from(
            Json(response.unwrap().into()),
            60 * 60, // 1h
        ))
    } else {
        Err(ResponseError::NotFound {
            response: content::Json(
                json!({
                    "message:": "Client not found",
                    "handle": handle
                })
                .to_string(),
            ),
        })
    }
}

impl From<rolodex_grpc::proto::UpdateClientResponse> for models::UpdateClientResponse {
    fn from(response: rolodex_grpc::proto::UpdateClientResponse) -> Self {
        use crate::optional::Optional;
        let client = response.client.unwrap();
        models::UpdateClientResponse {
            client_id: client.client_id,
            full_name: client.full_name,
            box_public_key: client.box_public_key,
            signing_public_key: client.signing_public_key,
            handle: client.handle.into_option(),
            profile: client.profile.into_option(),
            joined: client.joined,
            phone_sms_verified: client.phone_sms_verified,
            ral: client.ral,
            avatar_version: client.avatar_version,
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
    _ratelimited: guards::RateLimited,
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

    if (update_client_request.password_salt.is_some()
        && update_client_request.password_verifier.is_some())
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

        if let Some(password_salt) = &update_client_request.password_salt {
            if let Some(password_verifier) = &update_client_request.password_verifier {
                use data_encoding::BASE64URL_NOPAD;

                // Update password
                let response = rolodex_client.update_client_password(
                    rolodex_grpc::proto::UpdateClientPasswordRequest {
                        client_id: client_id.clone(),
                        password_verifier: BASE64URL_NOPAD
                            .decode(password_verifier.as_bytes())?
                            .to_vec(),
                        password_salt: BASE64URL_NOPAD.decode(password_salt.as_bytes())?.to_vec(),
                        location: location.clone(),
                    },
                )?;

                check_result(response.result)?;
            }
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
            client_id: client_id.clone(),
            full_name: update_client_request.full_name.clone(),
            box_public_key: update_client_request.box_public_key.clone(),
            signing_public_key: update_client_request.signing_public_key.clone(),
            handle: update_client_request
                .handle
                .clone()
                .unwrap_or_else(|| String::from("")),
            profile: update_client_request
                .profile
                .clone()
                .unwrap_or_else(|| String::from("")),

            // these fields are ignored but required by the proto definition
            joined: 0,                      // ignored
            phone_sms_verified: false,      // ignored
            ral: update_client_request.ral, // ignored
            avatar_version: 0,              // ignored
            referred_by: "".into(),         // ignored
        }),
        location,
    })?;

    check_result(response.result)?;

    let response: models::UpdateClientResponse = response.into();

    let response_inner = response.clone();
    std::thread::spawn(move || {
        // Lastly, invalidate the CDN caches in the background
        let _res = gcp::invalidate_cdn_cache_for_client(&client_id, &response_inner.handle);
    });

    // Update the index in elasticsearch. This is launched on a separate thread
    // so it doesn't block.
    let elastic_doc: elasticsearch::ClientProfileDocument = response.clone().into();
    std::thread::spawn(move || {
        let elastic = elasticsearch::ElasticSearchClient::new();
        elastic.update(elastic_doc);
    });

    Ok(Json(response))
}

#[get("/ping")]
pub fn get_ping(_ratelimited: guards::RateLimited) -> String {
    "pong".into()
}

#[get("/messages?<sketch>")]
pub fn get_messages(
    sketch: Option<String>,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<Vec<models::Message>>, ResponseError> {
    let switchroom_client = switchroom_client::Client::new(&config::CONFIG);

    let response = switchroom_client.get_messages(switchroom_grpc::proto::GetMessagesRequest {
        client_id: calling_client.client_id,
        sketch: sketch.unwrap_or_else(|| "".to_owned()),
    })?;

    Ok(Json(
        response
            .messages
            .iter()
            .map(models::Message::from)
            .collect(),
    ))
}

impl From<&models::Timestamp> for switchroom_grpc::proto::Timestamp {
    fn from(ts: &models::Timestamp) -> Self {
        Self {
            seconds: ts.seconds,
            nanos: ts.nanos,
        }
    }
}

impl From<&switchroom_grpc::proto::Timestamp> for models::Timestamp {
    fn from(ts: &switchroom_grpc::proto::Timestamp) -> Self {
        Self {
            seconds: ts.seconds,
            nanos: ts.nanos,
        }
    }
}

impl From<&switchroom_grpc::proto::Message> for models::Message {
    fn from(message: &switchroom_grpc::proto::Message) -> Self {
        use data_encoding::BASE64URL_NOPAD;
        let received_at = message.received_at.as_ref().unwrap();
        let sent_at = message.sent_at.as_ref().unwrap();
        models::Message {
            to: message.to.clone(),
            from: message.from.clone(),
            body: BASE64URL_NOPAD.encode(&message.body),
            hash: Some(BASE64URL_NOPAD.encode(&message.hash)),
            received_at: Some(received_at.into()),
            nonce: BASE64URL_NOPAD.encode(&message.nonce),
            sender_public_key: BASE64URL_NOPAD.encode(&message.sender_public_key),
            recipient_public_key: BASE64URL_NOPAD.encode(&message.recipient_public_key),
            sent_at: sent_at.into(),
            signature: Some(BASE64URL_NOPAD.encode(&message.signature)),
            value_cents: message.value_cents,
        }
    }
}

impl From<switchroom_grpc::proto::Message> for models::Message {
    fn from(message: switchroom_grpc::proto::Message) -> Self {
        models::Message::from(&message)
    }
}

fn check_box_public_keys(
    client: &rolodex_grpc::proto::Client,
    box_public_key: &str,
) -> Result<(), ResponseError> {
    if box_public_key.eq(&client.box_public_key) {
        Ok(())
    } else {
        Err(ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "message:": "Invalid box public key (didn't match the one on record)",
                    "found": box_public_key,
                    "expected": client.box_public_key
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
    use data_encoding::BASE64URL_NOPAD;
    use sodiumoxide::crypto::sign;

    let pk = sign::PublicKey::from_slice(
        &BASE64URL_NOPAD.decode(client.signing_public_key.as_bytes())?,
    )?;

    let signature = sign::Signature::from_slice(
        &BASE64URL_NOPAD.decode(message.signature.as_ref()?.as_bytes())?,
    )?;

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
                    "signing_public_key": client.signing_public_key,
                })
                .to_string(),
            ),
        })
    }
}

fn check_message_hash(message: &models::Message) -> Result<(), ResponseError> {
    use data_encoding::BASE64URL_NOPAD;
    use sodiumoxide::crypto::generichash;

    let mut hasher = generichash::State::new(32, None).unwrap();

    let message_json = serde_json::to_string(&models::Message {
        signature: None,
        hash: None,
        ..message.clone()
    })?;

    hasher.update(message_json.as_bytes()).unwrap();
    let digest = hasher.finalize().unwrap();
    let expected_hash = BASE64URL_NOPAD.encode(digest.as_ref());
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

#[post("/messages", data = "<messages>", format = "json")]
pub fn post_messages(
    messages: Result<Json<Vec<models::Message>>, JsonError>,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<Vec<models::Message>>, ResponseError> {
    use data_encoding::BASE64URL_NOPAD;

    let messages = match messages {
        Ok(messages) => messages,
        Err(err) => return Err(err.into()),
    };

    let mut sent_messages = vec![];

    let switchroom_client = switchroom_client::Client::new(&config::CONFIG);
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);
    let beancounter_client = beancounter_client::Client::new(&config::CONFIG);

    let sender_client = rolodex_client::get_client_for(
        &rolodex_client,
        &calling_client.client_id,
        &calling_client.client_id,
    )?;

    if !sender_client.phone_sms_verified {
        return Err(ResponseError::PhoneNotVerified {
            response: content::Json(
                json!({
                    "message:": "Client's phone number has not been verified",
                })
                .to_string(),
            ),
        });
    }

    for message in messages.iter() {
        // Verify the message hash
        check_message_hash(&message)?;

        // Verify the public key of the client sending this message matches what's
        // in our DB. Keep the client struct so we can verify the signature as well.
        check_box_public_keys(&sender_client, &message.sender_public_key)?;

        // Verify the public key of the recipient matches what's in our DB
        let recipient_client = rolodex_client::get_client_for(
            &rolodex_client,
            &calling_client.client_id,
            &message.to,
        )?;
        check_box_public_keys(&recipient_client, &message.recipient_public_key)?;

        // Verify the message signature
        check_message_signature(&sender_client, &message)?;

        let value_cents = std::cmp::max(message.value_cents, 0);
        let message_hash = BASE64URL_NOPAD.decode(message.hash.as_ref()?.as_bytes())?;

        let response = switchroom_client.send_message(switchroom_grpc::proto::Message {
            to: message.to.clone(),
            body: BASE64URL_NOPAD.decode(message.body.as_bytes())?,
            from: calling_client.client_id.clone(),
            hash: message_hash.clone(),
            received_at: None,
            nonce: BASE64URL_NOPAD.decode(message.nonce.as_bytes())?,
            sender_public_key: BASE64URL_NOPAD.decode(message.sender_public_key.as_bytes())?,
            recipient_public_key: BASE64URL_NOPAD
                .decode(message.recipient_public_key.as_bytes())?,
            sent_at: Some((&message.sent_at).into()),
            signature: BASE64URL_NOPAD.decode(message.signature.as_ref()?.as_bytes())?,
            value_cents,
        })?;

        let recipient_client_id = recipient_client.client_id.clone();
        let sender_client_name = sender_client.full_name.clone();
        let message_hash_inner = message_hash.clone();

        // execute in a background thread
        std::thread::spawn(move || {
            let _res = mailgun::send_new_message_email(
                recipient_client_id,
                recipient_client.ral,
                &sender_client_name,
                value_cents,
                &BASE64URL_NOPAD.encode(&message_hash_inner),
            );
        });

        if value_cents > 0 {
            let payment_response =
                beancounter_client.add_payment(beancounter_grpc::proto::AddPaymentRequest {
                    client_id_from: calling_client.client_id.clone(),
                    client_id_to: message.to.clone(),
                    message_hash,
                    payment_cents: value_cents,
                    is_promo: false,
                })?;

            // If there's an error, we return success anyway, as if everything's
            // okay. It shouldn't bubble up to the client. This, of course,
            // means we pay out of our own pocket when there are exceptions.
            if payment_response.result
                != beancounter_grpc::proto::add_payment_response::Result::Success as i32
            {
                error!("Adding payment failed: {:?}", payment_response.result);
            }
        }

        sent_messages.push(response.into());
    }

    Ok(Json(sent_messages))
}

impl From<beancounter_grpc::proto::SettlePaymentResponse> for models::SettlePaymentResponse {
    fn from(response: beancounter_grpc::proto::SettlePaymentResponse) -> Self {
        Self {
            fee_cents: response.fee_cents,
            payment_cents: response.payment_cents,
            balance: response
                .balance
                .map(models::Balance::from)
                .unwrap_or_else(models::Balance::default),
        }
    }
}

#[put("/messages/<message_hash>/settle")]
pub fn put_messages_settle(
    message_hash: String,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::SettlePaymentResponse>, ResponseError> {
    use data_encoding::BASE64URL_NOPAD;

    let beancounter_client = beancounter_client::Client::new(&config::CONFIG);

    let response =
        beancounter_client.settle_payment(beancounter_grpc::proto::SettlePaymentRequest {
            client_id: calling_client.client_id.clone(),
            message_hash: BASE64URL_NOPAD.decode(message_hash.as_bytes())?,
        })?;

    if response.ral >= 0 {
        let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

        let _response =
            rolodex_client.update_client_ral(rolodex_grpc::proto::UpdateClientRalRequest {
                client_id: calling_client.client_id.clone(),
                ral: response.ral,
            });
    }

    Ok(Json(response.into()))
}

impl From<beancounter_grpc::proto::Balance> for models::Balance {
    fn from(balance: beancounter_grpc::proto::Balance) -> Self {
        Self {
            client_id: balance.client_id,
            balance_cents: balance.balance_cents,
            promo_cents: balance.promo_cents,
            withdrawable_cents: balance.withdrawable_cents,
        }
    }
}

impl From<beancounter_grpc::proto::GetBalanceResponse> for models::GetAccountBalanceResponse {
    fn from(response: beancounter_grpc::proto::GetBalanceResponse) -> Self {
        Self {
            balance: response
                .balance
                .map(models::Balance::from)
                .unwrap_or_else(models::Balance::default),
        }
    }
}

#[get("/account/balance")]
pub fn get_account_balance(
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::GetAccountBalanceResponse>, ResponseError> {
    let beancounter_client = beancounter_client::Client::new(&config::CONFIG);

    let response = beancounter_client.get_balance(beancounter_grpc::proto::GetBalanceRequest {
        client_id: calling_client.client_id,
    })?;

    Ok(Json(response.into()))
}

impl From<beancounter_grpc::proto::StripeChargeResponse> for models::StripeChargeResponse {
    fn from(response: beancounter_grpc::proto::StripeChargeResponse) -> Self {
        use beancounter_grpc::proto::stripe_charge_response::Result;
        Self {
            result: match Result::from_i32(response.result) {
                Some(Result::Success) => "success",
                Some(Result::Failure) => "failure",
                _ => "unknown",
            }
            .into(),
            api_response: serde_json::from_str(&response.api_response).unwrap(),
            message: response.message,
            balance: match response.balance {
                Some(balance) => Some(balance.into()),
                _ => None,
            },
        }
    }
}

#[post("/account/charge", data = "<charge_request>", format = "json")]
pub fn post_stripe_charge(
    charge_request: Result<Json<models::StripeChargeRequest>, JsonError>,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::StripeChargeResponse>, ResponseError> {
    let charge_request = match charge_request {
        Ok(charge_request) => charge_request,
        Err(err) => return Err(err.into()),
    };

    let beancounter_client = beancounter_client::Client::new(&config::CONFIG);

    let response =
        beancounter_client.stripe_charge(beancounter_grpc::proto::StripeChargeRequest {
            client_id: calling_client.client_id,
            amount_cents: charge_request.amount_cents,
            token: serde_json::to_string(&charge_request.token)?,
        })?;

    Ok(Json(response.into()))
}

impl From<beancounter_grpc::proto::ConnectAccountPrefs> for models::ConnectAccountPrefs {
    fn from(proto: beancounter_grpc::proto::ConnectAccountPrefs) -> Self {
        Self {
            enable_automatic_payouts: proto.enable_automatic_payouts,
            automatic_payout_threshold_cents: proto.automatic_payout_threshold_cents,
        }
    }
}

impl From<beancounter_grpc::proto::ConnectAccountInfo> for models::ConnectAccountInfo {
    fn from(proto: beancounter_grpc::proto::ConnectAccountInfo) -> Self {
        use beancounter_grpc::proto::connect_account_info::Connect;
        use beancounter_grpc::proto::connect_account_info::State;
        Self {
            state: match State::from_i32(proto.state) {
                Some(State::Active) => "active",
                Some(State::Inactive) => "inactive",
                _ => "unknown",
            }
            .into(),
            login_link_url: proto
                .connect
                .as_ref()
                .map(|t| match t {
                    Connect::LoginLinkUrl(url) => Some(url.clone()),
                    _ => None,
                })
                .unwrap(),
            oauth_url: proto
                .connect
                .as_ref()
                .map(|t| match t {
                    Connect::OauthUrl(url) => Some(url.clone()),
                    _ => None,
                })
                .unwrap(),
            preferences: proto.preferences.unwrap().into(),
        }
    }
}

impl From<beancounter_grpc::proto::GetConnectAccountResponse>
    for models::GetConnectAccountResponse
{
    fn from(response: beancounter_grpc::proto::GetConnectAccountResponse) -> Self {
        Self {
            client_id: response.client_id,
            connect_account: response.connect_account.unwrap().into(),
        }
    }
}

fn eligible_for_connect(calling_client_id: &str) -> Result<bool, ResponseError> {
    use chrono::prelude::*;

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let response = rolodex_client.get_client(rolodex_grpc::proto::GetClientRequest {
        id: Some(rolodex_grpc::proto::get_client_request::Id::ClientId(
            calling_client_id.into(),
        )),
        calling_client_id: calling_client_id.into(),
    })?;

    // Client must have had an account for at least 7 days before becoming eligible
    Ok((Utc::now() - Utc.timestamp(response.client?.joined, 0)).num_days() >= 7)
}

fn ineligible_connect_account() -> models::ConnectAccountInfo {
    models::ConnectAccountInfo {
        state: "ineligible".into(),
        login_link_url: None,
        oauth_url: None,
        preferences: models::ConnectAccountPrefs::default(),
    }
}

#[get("/account/connect")]
pub fn get_account_connect(
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::GetConnectAccountResponse>, ResponseError> {
    // Determine client's eligibility first
    if !eligible_for_connect(&calling_client.client_id)? {
        return Ok(Json(models::GetConnectAccountResponse {
            client_id: calling_client.client_id,
            connect_account: ineligible_connect_account(),
        }));
    }

    let beancounter_client = beancounter_client::Client::new(&config::CONFIG);

    let response = beancounter_client.get_connect_account(
        beancounter_grpc::proto::GetConnectAccountRequest {
            client_id: calling_client.client_id,
        },
    )?;

    Ok(Json(response.into()))
}

impl From<beancounter_grpc::proto::CompleteConnectOauthResponse>
    for models::CompleteConnectOauthResponse
{
    fn from(response: beancounter_grpc::proto::CompleteConnectOauthResponse) -> Self {
        Self {
            client_id: response.client_id,
            connect_account: response.connect_account.unwrap().into(),
        }
    }
}

#[post("/account/oauth", data = "<connect_oauth>", format = "json")]
pub fn post_account_oauth(
    connect_oauth: Result<Json<models::CompleteConnectOauthRequest>, JsonError>,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::CompleteConnectOauthResponse>, ResponseError> {
    // Determine client's eligibility first
    if !eligible_for_connect(&calling_client.client_id)? {
        return Ok(Json(models::CompleteConnectOauthResponse {
            client_id: calling_client.client_id,
            connect_account: ineligible_connect_account(),
        }));
    }

    let connect_oauth = match connect_oauth {
        Ok(connect_oauth) => connect_oauth,
        Err(err) => return Err(err.into()),
    };

    let beancounter_client = beancounter_client::Client::new(&config::CONFIG);

    let response = beancounter_client.complete_connect_oauth(
        beancounter_grpc::proto::CompleteConnectOauthRequest {
            client_id: calling_client.client_id,
            authorization_code: connect_oauth.authorization_code.clone(),
            oauth_state: connect_oauth.oauth_state.clone(),
        },
    )?;

    Ok(Json(response.into()))
}

#[post("/account/connect/prefs", data = "<connect_prefs>", format = "json")]
pub fn post_account_connect_prefs(
    connect_prefs: Result<Json<models::ConnectAccountPrefs>, JsonError>,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::ConnectAccountInfo>, ResponseError> {
    let connect_prefs = match connect_prefs {
        Ok(connect_prefs) => connect_prefs,
        Err(err) => return Err(err.into()),
    };

    let beancounter_client = beancounter_client::Client::new(&config::CONFIG);

    let response = beancounter_client.update_connect_prefs(
        beancounter_grpc::proto::UpdateConnectAccountPrefsRequest {
            client_id: calling_client.client_id,
            preferences: Some(beancounter_grpc::proto::ConnectAccountPrefs {
                enable_automatic_payouts: connect_prefs.enable_automatic_payouts,
                automatic_payout_threshold_cents: connect_prefs.automatic_payout_threshold_cents,
            }),
        },
    )?;

    Ok(Json(response.connect_account.unwrap().into()))
}

impl From<beancounter_grpc::proto::ConnectPayoutResponse> for models::ConnectPayoutResponse {
    fn from(response: beancounter_grpc::proto::ConnectPayoutResponse) -> Self {
        use beancounter_grpc::proto::connect_payout_response::Result;
        Self {
            result: match Result::from_i32(response.result) {
                Some(Result::Success) => "success",
                Some(Result::InsufficientBalance) => "insufficient_balance",
                Some(Result::InvalidAmount) => "invalid_amount",
                _ => "unknown",
            }
            .into(),
            balance: response.balance.unwrap().into(),
        }
    }
}

#[post("/account/connect/payout", data = "<connect_payout>", format = "json")]
pub fn post_account_connect_payout(
    connect_payout: Result<Json<models::ConnectPayoutRequest>, JsonError>,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::ConnectPayoutResponse>, ResponseError> {
    let connect_payout = match connect_payout {
        Ok(connect_payout) => connect_payout,
        Err(err) => return Err(err.into()),
    };

    let beancounter_client = beancounter_client::Client::new(&config::CONFIG);

    let response =
        beancounter_client.connect_payout(beancounter_grpc::proto::ConnectPayoutRequest {
            client_id: calling_client.client_id,
            amount_cents: connect_payout.amount_cents,
        })?;

    Ok(Json(response.into()))
}

impl From<&beancounter_grpc::proto::Timestamp> for models::Timestamp {
    fn from(ts: &beancounter_grpc::proto::Timestamp) -> Self {
        Self {
            seconds: ts.seconds,
            nanos: ts.nanos,
        }
    }
}

impl From<beancounter_grpc::proto::Transaction> for models::Transaction {
    fn from(tx: beancounter_grpc::proto::Transaction) -> Self {
        use beancounter_grpc::proto::transaction::{Reason, Type};
        Self {
            created_at: tx.created_at.as_ref().unwrap().into(),
            tx_type: match Type::from_i32(tx.tx_type) {
                Some(Type::Debit) => "debit",
                Some(Type::Credit) => "credit",
                Some(Type::PromoCredit) => "promo credit",
                Some(Type::PromoDebit) => "promo debit",
                _ => "unknown",
            }
            .to_string(),
            tx_reason: match Reason::from_i32(tx.tx_reason) {
                Some(Reason::MessageRead) => "message read",
                Some(Reason::MessageUnread) => "message unread",
                Some(Reason::MessageSent) => "message sent",
                Some(Reason::CreditAdded) => "credit added",
                Some(Reason::Payout) => "payout",
                _ => "unknown",
            }
            .to_string(),
            amount_cents: tx.amount_cents,
        }
    }
}

#[get("/account/transactions?<limit>")]
pub fn get_account_transactions(
    limit: Option<i64>,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<Vec<models::Transaction>>, ResponseError> {
    let beancounter_client = beancounter_client::Client::new(&config::CONFIG);

    let response =
        beancounter_client.get_transactions(beancounter_grpc::proto::GetTransactionsRequest {
            client_id: calling_client.client_id,
            limit: match limit {
                Some(limit) => limit,
                None => 0,
            },
        })?;

    Ok(Json(
        response
            .transactions
            .into_iter()
            .map(models::Transaction::from)
            .collect(),
    ))
}

impl From<beancounter_grpc::proto::AmountByDate> for models::AmountByDate {
    fn from(data: beancounter_grpc::proto::AmountByDate) -> Self {
        Self {
            amount_cents: data.amount_cents,
            year: data.year,
            month: data.month,
            day: data.day,
        }
    }
}

impl From<beancounter_grpc::proto::GetStatsResponse> for models::Stats {
    fn from(response: beancounter_grpc::proto::GetStatsResponse) -> Self {
        Self {
            message_read_amount: response
                .message_read_amount
                .into_iter()
                .map(models::AmountByDate::from)
                .collect(),
            message_sent_amount: response
                .message_sent_amount
                .into_iter()
                .map(models::AmountByDate::from)
                .collect(),
        }
    }
}

#[get("/stats")]
pub fn get_stats(_ratelimited: guards::RateLimited) -> Result<Json<models::Stats>, ResponseError> {
    let beancounter_client = beancounter_client::Client::new(&config::CONFIG);

    let response = beancounter_client.get_stats(beancounter_grpc::proto::GetStatsRequest {})?;

    Ok(Json(response.into()))
}

impl From<elastic::Error> for ResponseError {
    fn from(err: elastic::Error) -> Self {
        Self::InternalError {
            response: content::Json(
                json!({
                    "message:": "Search failed",
                    "err":err.to_string()
                })
                .to_string(),
            ),
        }
    }
}

#[post("/client/search/<prefix>")]
pub fn post_client_search(
    prefix: String,
    _calling_client: Option<guards::Client>,
    _ratelimited: guards::RateLimited,
) -> Result<Cached<Json<Vec<elasticsearch::ClientProfileDocument>>>, ResponseError> {
    let elastic = elasticsearch::ElasticSearchClient::new();
    let response = elastic.search_suggest(&prefix)?;

    Ok(Cached::from(Json(response), 60))
}

#[post("/client/verify_phone/<code>")]
pub fn post_client_verify_phone(
    code: i32,
    calling_client: guards::Client,
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::VerifyPhoneResponse>, ResponseError> {
    let location = utils::make_location(client_ip, geo_headers);
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let response = rolodex_client.verify_phone(rolodex_grpc::proto::VerifyPhoneRequest {
        client_id: calling_client.client_id.clone(),
        code,
        location,
    })?;

    if response.result == rolodex_grpc::proto::Result::Success as i32 {
        std::thread::spawn(move || {
            // Invalidate the CDN caches in the background
            let _res = gcp::invalidate_cdn_cache(&format!("/client/{}", calling_client.client_id));
        });
        match response.client.as_ref() {
            Some(client) => {
                if !client.referred_by.is_empty() && config::CONFIG.referrals.enabled {
                    let referred_by = client.referred_by.clone();
                    std::thread::spawn(move || {
                        let beancounter_client = beancounter_client::Client::new(&config::CONFIG);
                        let _res = beancounter_client.add_promo(
                            beancounter_grpc::proto::AddPromoRequest {
                                client_id: referred_by,
                                amount_cents: config::CONFIG.referrals.promo_amount * 100,
                            },
                        );
                    });
                }
            }
            None => (),
        }
        Ok(Json(models::VerifyPhoneResponse {
            result: "success".to_owned(),
            client: Some(response.client.into()),
        }))
    } else {
        Ok(Json(models::VerifyPhoneResponse {
            result: "invalid code".to_owned(),
            client: None,
        }))
    }
}

#[post("/client/verify_phone")]
pub fn post_client_verify_phone_new_code(
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::SendVerificationCodeResponse>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);
    rolodex_client.send_verification_code(rolodex_grpc::proto::SendVerificationCodeRequest {
        client_id: calling_client.client_id.clone(),
    })?;

    Ok(Json(models::SendVerificationCodeResponse {}))
}

impl From<Option<rolodex_grpc::proto::Prefs>> for models::ClientPrefs {
    fn from(prefs: Option<rolodex_grpc::proto::Prefs>) -> Self {
        Self {
            email_notifications: match prefs {
                Some(prefs) => prefs.email_notifications,
                _ => "ral".into(),
            },
        }
    }
}

#[get("/client/<arg_client_id>/prefs")]
pub fn get_client_prefs(
    arg_client_id: String,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::ClientPrefs>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let fetch_client_id = if arg_client_id == "self" {
        calling_client.client_id
    } else {
        if arg_client_id != calling_client.client_id {
            return Err(ResponseError::Unauthorized {
                response: content::Json(
                    json!({
                        "message:": "Authentication required",
                    })
                    .to_string(),
                ),
            });
        }
        arg_client_id
    };

    let response = rolodex_client.get_prefs(rolodex_grpc::proto::GetPrefsRequest {
        client_id: fetch_client_id,
    })?;

    Ok(Json(response.prefs.into()))
}

#[put("/client/<arg_client_id>/prefs", data = "<prefs>", format = "json")]
pub fn put_client_prefs(
    arg_client_id: String,
    calling_client: guards::Client,
    prefs: Result<Json<models::ClientPrefs>, JsonError>,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::ClientPrefs>, ResponseError> {
    let prefs = prefs?;

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let fetch_client_id = if arg_client_id == "self" {
        calling_client.client_id
    } else {
        if arg_client_id != calling_client.client_id {
            return Err(ResponseError::Unauthorized {
                response: content::Json(
                    json!({
                        "message:": "Authentication required",
                    })
                    .to_string(),
                ),
            });
        }
        arg_client_id
    };

    let response = rolodex_client.update_prefs(rolodex_grpc::proto::UpdatePrefsRequest {
        client_id: fetch_client_id,
        prefs: Some(rolodex_grpc::proto::Prefs {
            email_notifications: prefs.email_notifications.clone(),
        }),
    })?;

    Ok(Json(response.prefs.into()))
}

#[get("/referrals")]
pub fn get_referrals(
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<Vec<models::GetClientResponse>>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let response = rolodex_client.get_referrals(rolodex_grpc::proto::GetReferralsRequest {
        referred_by_client_id: calling_client.client_id,
    })?;

    Ok(Json(
        response
            .referrals
            .into_iter()
            .map(models::GetClientResponse::from)
            .collect(),
    ))
}
