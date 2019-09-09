use crate::config;
use crate::error::ResponseError;
use crate::rolodex_client;

use instrumented::instrument;
use reqwest;
use rolodex_grpc;

#[derive(Serialize, Debug)]
struct NewMessageTemplate<'a> {
    from_name: &'a str,
    value_dollars: i32,
    message_hash: &'a str,
    site_uri: &'a str,
}

#[derive(Serialize, Debug)]
struct EmailFormParams<'a> {
    from: &'a str,
    to: &'a str,
    subject: &'a str,
    template: &'a str,
}

//  curl -s --user 'api:ENTER_API_KEY_HERE' \
// 	 https://api.mailgun.net/v3/noreply.umpyre.com/messages \
// 	 -F from='Mailgun Sandbox <postmaster@noreply.umpyre.com>' \
// 	 -F to='Brenden Matthews <brenden@umpyre.com>' \
// 	 -F subject='Hello Brenden Matthews' \
// 	 -F template='newmessage' \
// 	 -F h:X-Mailgun-Variables='{"test": "test"}'

#[instrument(INFO)]
pub fn send_new_message_email(
    recipient_client_id: String,
    from_name: &str,
    value_cents: i32,
    message_hash: &str,
) -> Result<(), ResponseError> {
    if config::CONFIG.mailgun.api_key.is_empty() {
        // noop, don't send mail
        return Ok(());
    }

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);
    let email = rolodex_client.get_client_email(rolodex_grpc::proto::GetClientEmailRequest {
        client_id: recipient_client_id,
    })?;

    let form_params = EmailFormParams {
        to: &email.email_as_entered,
        from: "Umpyre <umpyre@noreply.umpyre.com>",
        subject: &format!("New message from {}", from_name),
        template: "newmessage",
    };
    let template = NewMessageTemplate {
        from_name,
        value_dollars: (f64::from(value_cents) / 100.0).round() as i32,
        message_hash,
        site_uri: &config::CONFIG.service.site_uri,
    };

    let client = reqwest::Client::new();

    client
        .post(&format!("{}/messages", config::CONFIG.mailgun.url))
        .form(&form_params)
        .header(
            reqwest::header::HeaderName::from_static("X-Mailgun-Variables"),
            &serde_json::to_string(&template).unwrap(),
        )
        .send()?;

    Ok(())
}
