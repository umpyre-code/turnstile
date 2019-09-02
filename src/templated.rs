use crate::config;
use crate::error::ResponseError;
use crate::guards;
use crate::responders::Cached;
use crate::rolodex_client;

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
    width: i32,
    height: i32,
    font_size: i32,
}

fn get_badge_svg_inner(
    client_id: String,
    name: Option<String>,
    width: Option<i32>,
    height: Option<i32>,
    font_size: Option<i32>,
) -> Result<String, ResponseError> {
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
                name: name.unwrap_or_else(|| full_name.to_owned()),
                width: width.unwrap_or_else(|| 151),
                height: height.unwrap_or_else(|| 50),
                font_size: font_size.unwrap_or_else(|| 12),
            };
            Ok(TERA.render("badge.svg", &badge)?)
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

#[get("/badge/<client_id>/badge.svg?<name>&<width>&<height>&<font_size>")]
pub fn get_badge_svg(
    client_id: String,
    name: Option<String>,
    width: Option<i32>,
    height: Option<i32>,
    font_size: Option<i32>,
    _ratelimited: guards::RateLimited,
) -> Result<Cached<Svg>, ResponseError> {
    Ok(Cached::from(
        Svg(get_badge_svg_inner(
            client_id, name, width, height, font_size,
        )?),
        3600,
    ))
}

#[derive(Responder)]
#[response(content_type = "image/png")]
pub struct Png(Vec<u8>);

#[get("/badge/<client_id>/badge.png?<name>&<width>&<height>&<font_size>")]
pub fn get_badge_png(
    client_id: String,
    name: Option<String>,
    width: Option<i32>,
    height: Option<i32>,
    font_size: Option<i32>,
    _ratelimited: guards::RateLimited,
) -> Result<Cached<Png>, ResponseError> {
    use resvg::prelude::*;
    use std::io::Read;
    use tempfile::NamedTempFile;

    let svg = get_badge_svg_inner(client_id, name, width, height, font_size)?;

    let mut opt = resvg::Options::default();
    opt.usvg.dpi = 300.0;
    let rtree = usvg::Tree::from_str(&svg, &opt.usvg)?;

    let backend = resvg::default_backend();

    let mut img = backend.render_to_image(&rtree, &opt)?;
    let file = NamedTempFile::new()?;
    img.save_png(file.path());

    let mut png = Vec::new();
    file.as_file().read_to_end(&mut png)?;

    Ok(Cached::from(Png(png), 3600))
}
