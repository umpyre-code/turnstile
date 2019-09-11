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
    #[serde(rename(serialize = "h:X-Mailgun-Variables"))]
    variables: &'a str,
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
    recipient_client_ral: i32,
    from_name: &str,
    value_cents: i32,
    message_hash: &str,
) -> Result<(), ResponseError> {
    if config::CONFIG.mailgun.api_key.is_empty() {
        // noop, don't send mail
        return Ok(());
    }

    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);
    // Fetch recipient's notification prefs
    let client_prefs = rolodex_client.get_prefs(rolodex_grpc::proto::GetPrefsRequest {
        client_id: recipient_client_id.clone(),
    })?;

    match client_prefs.prefs {
        Some(prefs) => match prefs.email_notifications.as_ref() {
            pref @ "ral" | pref @ "always" => {
                // if this message value is at or above RAL, send an email notification
                if pref == "always"
                    || (f64::from(value_cents) / 100.0).round() >= f64::from(recipient_client_ral)
                {
                    let email = rolodex_client.get_client_email(
                        rolodex_grpc::proto::GetClientEmailRequest {
                            client_id: recipient_client_id,
                        },
                    )?;

                    let template = NewMessageTemplate {
                        from_name,
                        value_dollars: (f64::from(value_cents) / 100.0).round() as i32,
                        message_hash,
                        site_uri: &config::CONFIG.service.web_uri,
                    };
                    let form_params = EmailFormParams {
                        to: &email.email_as_entered,
                        from: "Umpyre <umpyre@noreply.umpyre.com>",
                        subject: &format!("New message from {}", from_name),
                        template: "newmessage",
                        variables: &serde_json::to_string(&template).unwrap(),
                    };

                    let client = reqwest::Client::new();

                    client
                        .post(&format!("{}/messages", config::CONFIG.mailgun.url))
                        .basic_auth("api", Some(&config::CONFIG.mailgun.api_key))
                        .form(&form_params)
                        .send()?;
                }
            }
            _ => (),
        },
        _ => (),
    }
    Ok(())
}
