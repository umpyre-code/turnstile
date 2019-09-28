use data_encoding::BASE64URL_NOPAD;
use serde_json;
use tera::Tera;

use crate::beancounter_client;
use crate::config;
use crate::error::ResponseError;
use crate::models::{SendMessage, Timestamp};
use crate::switchroom_client;

lazy_static! {
    pub static ref TERA: Tera = {
        let mut tera = Tera::default();
        tera.add_raw_templates(vec![("welcome.md", include_str!("templates/welcome.md"))])
            .expect("failed to add tera templates");
        tera
    };
}

fn encrypt_body(
    account: &config::Account,
    recipient_public_key: &str,
    body: &str,
) -> (String, String) {
    use sodiumoxide::crypto::box_;

    let theirpk = box_::PublicKey::from_slice(
        &BASE64URL_NOPAD
            .decode(recipient_public_key.as_bytes())
            .unwrap(),
    )
    .unwrap();
    let oursk = box_::SecretKey::from_slice(
        &BASE64URL_NOPAD
            .decode(account.box_secret_key.as_bytes())
            .unwrap(),
    )
    .unwrap();

    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(body.as_bytes(), &nonce, &theirpk, &oursk);

    (
        BASE64URL_NOPAD.encode(&ciphertext),
        BASE64URL_NOPAD.encode(nonce.as_ref()),
    )
}

fn b2b_hash(s: &str, digest_size: usize) -> String {
    use sodiumoxide::crypto::generichash;
    let mut hasher = generichash::State::new(digest_size, None).unwrap();
    hasher.update(s.as_bytes()).unwrap();
    let digest = hasher.finalize().unwrap();
    BASE64URL_NOPAD.encode(digest.as_ref())
}

#[derive(Serialize)]
pub struct Welcome<'a> {
    first_name: &'a str,
    value: i32,
    client_id: &'a str,
    referral_promo_amount: i32,
}

#[derive(Serialize)]
pub struct Body {
    markdown: String,
    r#type: String,
    pda: String,
}

pub fn create_welcome_message(
    to: &str,
    recipient_public_key: &str,
    first_name: &str,
) -> Result<(), ResponseError> {
    use sodiumoxide::crypto::sign;
    use std::time::SystemTime;

    let account = &config::CONFIG.system_account;

    let welcome = Welcome {
        first_name,
        value: account.welcome_promo_amount,
        client_id: to,
        referral_promo_amount: config::CONFIG.referrals.promo_amount,
    };
    let body = serde_json::to_string(&Body {
        markdown: TERA.render("welcome.md", &welcome)?,
        r#type: "@@message/message".into(),
        pda: "Welcome to Umpyre 🥳🎉".into(),
    })
    .unwrap();
    let (body, nonce) = encrypt_body(account, recipient_public_key, &body);

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();

    // Create message
    let message = SendMessage {
        body,
        nonce,
        from: account.client_id.clone(),
        hash: None,
        recipient_public_key: recipient_public_key.into(),
        sender_public_key: account.box_public_key.clone(),
        sent_at: Timestamp {
            nanos: now.subsec_nanos() as i32,
            seconds: now.as_secs() as i64,
        },
        signature: None,
        to: to.into(),
        value_cents: 100 * account.welcome_promo_amount,
    };

    // Compute hash
    let message_json = serde_json::to_string(&message).unwrap();
    let hash = b2b_hash(&message_json, 32);
    let message = SendMessage {
        hash: Some(hash),
        ..message
    };

    // Compute signature
    let message_json = serde_json::to_string(&message).unwrap();
    let signing_secret_key = sign::SecretKey::from_slice(
        &BASE64URL_NOPAD
            .decode(account.signing_secret_key.as_bytes())
            .unwrap(),
    )
    .unwrap();

    let signature = BASE64URL_NOPAD
        .encode(&sign::sign_detached(message_json.as_bytes(), &signing_secret_key).as_ref());
    let message = SendMessage {
        signature: Some(signature),
        ..message
    };

    let beancounter_client = beancounter_client::Client::new(&config::CONFIG);
    beancounter_client.add_payment(beancounter_grpc::proto::AddPaymentRequest {
        client_id_from: account.client_id.clone(),
        client_id_to: message.to.clone(),
        message_hash: BASE64URL_NOPAD.decode(message.hash.as_ref().unwrap().as_bytes())?,
        payment_cents: 100 * account.welcome_promo_amount,
        is_promo: true,
    })?;

    let switchroom_client = switchroom_client::Client::new(&config::CONFIG);
    switchroom_client.send_message(switchroom_grpc::proto::Message {
        to: message.to.clone(),
        body: BASE64URL_NOPAD.decode(message.body.as_bytes())?,
        from: message.from.clone(),
        hash: BASE64URL_NOPAD.decode(message.hash.unwrap().as_bytes())?,
        received_at: None,
        nonce: BASE64URL_NOPAD.decode(message.nonce.as_bytes())?,
        sender_public_key: BASE64URL_NOPAD.decode(message.sender_public_key.as_bytes())?,
        recipient_public_key: BASE64URL_NOPAD.decode(message.recipient_public_key.as_bytes())?,
        sent_at: Some(switchroom_grpc::proto::Timestamp {
            seconds: message.sent_at.seconds,
            nanos: message.sent_at.nanos,
        }),
        signature: BASE64URL_NOPAD.decode(message.signature.as_ref()?.as_bytes())?,
        value_cents: 100 * account.welcome_promo_amount,
    })?;

    Ok(())
}
