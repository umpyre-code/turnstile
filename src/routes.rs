use crate::auth;
use crate::beancounter_client;
use crate::config;
use crate::error::ResponseError;
use crate::fairings;
use crate::guards;
use crate::models;
use crate::rolodex_client;
use crate::switchroom_client;
use crate::utils;

use rocket::http::RawStr;
use rocket::response::content;
use rocket_contrib::json::Json;
use rocket_contrib::json::JsonError;

use crate::responders::Cached;

fn handle_auth_handshake(
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    auth_request: &Result<Json<models::AuthHandshakeRequest>, JsonError>,
) -> Result<Json<models::AuthHandshakeResponse>, ResponseError> {
    use data_encoding::BASE64_NOPAD;

    let auth_request = match auth_request {
        Ok(auth_request) => auth_request,
        Err(err) => return Err(err.into()),
    };

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let location = utils::make_location(client_ip, geo_headers);

    let response = rolodex_client.auth_handshake(rolodex_grpc::proto::AuthHandshakeRequest {
        email: auth_request.email.clone(),
        a_pub: BASE64_NOPAD.decode(auth_request.a_pub.as_bytes())?.to_vec(),
        location,
    })?;

    Ok(Json(models::AuthHandshakeResponse {
        salt: BASE64_NOPAD.encode(&response.salt),
        b_pub: BASE64_NOPAD.encode(&response.b_pub),
    }))
}

fn handle_auth_verify(
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    auth_request: &Result<Json<models::AuthVerifyRequest>, JsonError>,
) -> Result<rolodex_grpc::proto::AuthVerifyResponse, ResponseError> {
    use data_encoding::BASE64_NOPAD;

    let auth_request = match auth_request {
        Ok(auth_request) => auth_request,
        Err(err) => return Err(err.into()),
    };

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let location = utils::make_location(client_ip, geo_headers);

    let response = rolodex_client.auth_verify(rolodex_grpc::proto::AuthVerifyRequest {
        email: auth_request.email.clone(),
        a_pub: BASE64_NOPAD.decode(auth_request.a_pub.as_bytes())?.to_vec(),
        client_proof: BASE64_NOPAD
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
    redis_writer: fairings::RedisWriter,
    auth_request: Result<Json<models::AuthVerifyRequest>, JsonError>,
) -> Result<Json<models::AuthVerifyResponse>, ResponseError> {
    use data_encoding::BASE64_NOPAD;

    let response = handle_auth_verify(client_ip, geo_headers, &auth_request)?;

    let jwt = auth::generate_auth_token(&*redis_writer, &response.client_id)?;

    Ok(Json(models::AuthVerifyResponse {
        client_id: response.client_id,
        server_proof: BASE64_NOPAD.encode(&response.server_proof),
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
    _redis_writer: fairings::RedisWriter,
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
    redis_writer: fairings::RedisWriter,
    auth_request: Result<Json<models::AuthVerifyRequest>, JsonError>,
) -> Result<Json<models::AuthVerifyResponse>, ResponseError> {
    use data_encoding::BASE64_NOPAD;

    let response = handle_auth_verify(client_ip, geo_headers, &auth_request)?;

    let jwt = auth::generate_auth_temporary_token(&*redis_writer, &response.client_id)?;

    Ok(Json(models::AuthVerifyResponse {
        client_id: response.client_id,
        server_proof: BASE64_NOPAD.encode(&response.server_proof),
        jwt,
    }))
}

#[post("/client", data = "<new_client_request>", format = "json")]
pub fn post_client(
    _ratelimited: guards::RateLimited,
    client_ip: guards::ClientIP,
    geo_headers: Option<guards::GeoHeaders>,
    redis_writer: fairings::RedisWriter,
    new_client_request: Result<Json<models::NewClientRequest>, JsonError>,
) -> Result<Json<models::NewClientResponse>, ResponseError> {
    use data_encoding::BASE64_NOPAD;

    let new_client_request = match new_client_request {
        Ok(new_client_request) => new_client_request,
        Err(err) => return Err(err.into()),
    };

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let location = utils::make_location(client_ip, geo_headers);

    let response = rolodex_client.add_client(rolodex_grpc::proto::NewClientRequest {
        full_name: new_client_request.full_name.clone(),
        password_verifier: BASE64_NOPAD
            .decode(new_client_request.password_verifier.as_bytes())?
            .to_vec(),
        password_salt: BASE64_NOPAD
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
    })?;

    let jwt = auth::generate_auth_token(&*redis_writer, &response.client_id)?;

    Ok(Json(models::NewClientResponse {
        client_id: response.client_id,
        jwt,
    }))
}

impl From<rolodex_grpc::proto::GetClientResponse> for models::GetClientResponse {
    fn from(response: rolodex_grpc::proto::GetClientResponse) -> Self {
        use crate::optional::Optional;
        let client = response.client.unwrap();
        models::GetClientResponse {
            client_id: client.client_id,
            full_name: client.full_name,
            box_public_key: client.box_public_key,
            signing_public_key: client.signing_public_key,
            handle: client.handle.into_option(),
            profile: client.profile.into_option(),
            joined: client.joined,
        }
    }
}

#[get("/client/<client_id>")]
pub fn get_client(
    client_id: String,
    calling_client: Option<guards::Client>,
    _ratelimited: guards::RateLimited,
) -> Result<Cached<Json<models::GetClientResponse>>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

    let response = rolodex_client.get_client(rolodex_grpc::proto::GetClientRequest {
        id: Some(rolodex_grpc::proto::get_client_request::Id::ClientId(
            client_id.clone(),
        )),
        calling_client_id: match calling_client {
            Some(client) => client.client_id,
            _ => "".to_string(),
        },
    });

    if response.is_ok() {
        Ok(Cached::from(Json(response.unwrap().into()), 60))
    } else {
        Err(ResponseError::NotFound {
            response: content::Json(
                json!({
                    "message:": "Client not found",
                    "client_id": client_id
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
        Ok(Cached::from(Json(response.unwrap().into()), 60))
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
                use data_encoding::BASE64_NOPAD;

                // Update password
                let response = rolodex_client.update_client_password(
                    rolodex_grpc::proto::UpdateClientPasswordRequest {
                        client_id: client_id.clone(),
                        password_verifier: BASE64_NOPAD
                            .decode(password_verifier.as_bytes())?
                            .to_vec(),
                        password_salt: BASE64_NOPAD.decode(password_salt.as_bytes())?.to_vec(),
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
            client_id,
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
        }),
        location,
    })?;

    check_result(response.result)?;

    Ok(Json(response.into()))
}

#[get("/ping")]
pub fn get_ping(_ratelimited: guards::RateLimited) -> String {
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

#[get("/messages?<sketch>")]
pub fn get_messages(
    sketch: Option<&RawStr>,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::GetMessagesResponse>, ResponseError> {
    let switchroom_client = switchroom_client::Client::new(&config::CONFIG);

    let response = switchroom_client.get_messages(switchroom_grpc::proto::GetMessagesRequest {
        client_id: calling_client.client_id,
        sketch: sketch
            .unwrap_or_else(|| RawStr::from_str(""))
            .as_str()
            .to_string(),
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
        id: Some(rolodex_grpc::proto::get_client_request::Id::ClientId(
            client_id.into(),
        )),
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

    let pk =
        sign::PublicKey::from_slice(&BASE64_NOPAD.decode(client.signing_public_key.as_bytes())?)?;

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
                    "signing_public_key": client.signing_public_key,
                })
                .to_string(),
            ),
        })
    }
}

fn check_message_hash(message: &models::Message) -> Result<(), ResponseError> {
    use data_encoding::BASE64_NOPAD;
    use sodiumoxide::crypto::generichash;

    let mut hasher = generichash::State::new(32, None).unwrap();

    let message_json = serde_json::to_string(&models::Message {
        signature: None,
        hash: None,
        ..message.clone()
    })?;

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
    _ratelimited: guards::RateLimited,
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

impl From<beancounter_grpc::proto::Balance> for models::Balance {
    fn from(balance: beancounter_grpc::proto::Balance) -> Self {
        Self {
            client_id: balance.client_id,
            balance_cents: balance.balance_cents,
            promo_cents: balance.promo_cents,
        }
    }
}
impl From<beancounter_grpc::proto::GetBalanceResponse> for models::GetAccountBalanceResponse {
    fn from(response: beancounter_grpc::proto::GetBalanceResponse) -> Self {
        if let Some(balance) = response.balance {
            Self {
                balance: balance.into(),
            }
        } else {
            Self {
                balance: models::Balance::default(),
            }
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
                Some(balance) => Some(models::Balance {
                    client_id: balance.client_id,
                    balance_cents: balance.balance_cents,
                    promo_cents: balance.promo_cents,
                }),
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

#[get("/account/connect")]
pub fn get_account_connect(
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<models::GetConnectAccountResponse>, ResponseError> {
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
