use crate::config;
use crate::error::ResponseError;
use crate::guards;
use crate::responders::Cached;
use crate::rolodex_client;

use rocket::http::RawStr;
use rocket::response::content;
use tera::Tera;

lazy_static! {
    pub static ref TERA: Tera = {
        let mut tera = Tera::default();
        tera.add_raw_templates(vec![("badge.svg", include_str!("templates/badge.svg"))])
            .expect("failed to add tera templates");
        tera
    };
}

#[derive(Responder)]
#[response(content_type = "image/svg+xml")]
pub struct Svg(String);

#[derive(Serialize)]
pub struct Badge {
    name: String,
}

#[get("/badge/<client_id>/badge.svg?<name>")]
pub fn get_badge(
    client_id: String,
    name: Option<&RawStr>,
    _ratelimited: guards::RateLimited,
) -> Result<Cached<Svg>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);
    let client = rolodex_client.get_client(rolodex_grpc::proto::GetClientRequest {
        calling_client_id: "".to_owned(),
        id: Some(rolodex_grpc::proto::get_client_request::Id::ClientId(
            client_id.clone(),
        )),
    });

    match client {
        Ok(client) => {
            let full_name = match &client.client {
                Some(client) => &client.full_name,
                None => "",
            };
            let badge = Badge {
                name: name
                    .unwrap_or_else(|| RawStr::from_str(full_name))
                    .as_str()
                    .to_string(),
            };
            Ok(Cached::from(Svg(TERA.render("badge.svg", &badge)?), 3600))
        }
        Err(_) => Err(ResponseError::NotFound {
            response: content::Json(
                json!({
                    "message": "Client not found",
                    "client_id": client_id
                })
                .to_string(),
            ),
        }),
    }
}