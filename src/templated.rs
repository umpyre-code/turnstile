use crate::config;
use crate::error::ResponseError;
use crate::guards;
use crate::responders::Cached;
use crate::responders::{Png, Svg};
use crate::rolodex_client;

use rocket::response::content;
use tera::Tera;

lazy_static! {
    pub static ref TERA: Tera = {
        let mut tera = Tera::default();
        tera.add_raw_templates(vec![
            (
                "badge-dark-svg.svg",
                include_str!("templates/badge-dark-svg.svg"),
            ),
            (
                "badge-light-svg.svg",
                include_str!("templates/badge-light-svg.svg"),
            ),
            (
                "badge-dark-png.svg",
                include_str!("templates/badge-dark-png.svg"),
            ),
            (
                "badge-light-png.svg",
                include_str!("templates/badge-light-png.svg"),
            ),
        ])
        .expect("failed to add tera templates");
        tera
    };
}

#[derive(Serialize)]
pub struct Badge {
    name: String,
    width: f64,
    height: f64,
    font_size: f64,
}

fn get_badge_svg_inner(
    client_id: String,
    name: Option<String>,
    width: Option<f64>,
    height: Option<f64>,
    font_size: Option<f64>,
    style: Option<String>,
    format: &str,
) -> Result<String, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);
    let client = rolodex_client.get_client(rolodex_grpc::proto::GetClientRequest {
        calling_client_id: "".to_owned(),
        id: Some(rolodex_grpc::proto::get_client_request::Id::ClientId(
            client_id.clone(),
        )),
    });

    let style = match style.as_ref() {
        Some(style) => match style.as_ref() {
            "light" | "dark" => style,
            _ => "light",
        },
        _ => "light",
    };

    match client {
        Ok(client) => {
            let full_name = match &client.client {
                Some(client) => &client.full_name,
                None => "",
            };
            let badge = Badge {
                name: name.unwrap_or_else(|| full_name.to_owned()),
                width: width.unwrap_or_else(|| 156.5),
                height: height.unwrap_or_else(|| 50.4),
                font_size: font_size.unwrap_or_else(|| 12.0),
            };
            Ok(TERA.render(&format!("badge-{}-{}.svg", style, format), &badge)?)
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

#[get("/badge/<client_id>/badge.svg?<name>&<width>&<height>&<font_size>&<style>")]
pub fn get_badge_svg(
    client_id: String,
    name: Option<String>,
    width: Option<f64>,
    height: Option<f64>,
    font_size: Option<f64>,
    style: Option<String>,
    _ratelimited: guards::RateLimited,
) -> Result<Cached<Svg>, ResponseError> {
    Ok(Cached::from(
        Svg(get_badge_svg_inner(
            client_id, name, width, height, font_size, style, "svg",
        )?),
        3600,
    ))
}

#[get("/badge/<client_id>/badge.png?<name>&<width>&<height>&<font_size>&<style>")]
pub fn get_badge_png(
    client_id: String,
    name: Option<String>,
    width: Option<f64>,
    height: Option<f64>,
    font_size: Option<f64>,
    style: Option<String>,
    _ratelimited: guards::RateLimited,
) -> Result<Cached<Png>, ResponseError> {
    use resvg::prelude::*;
    use std::io::Read;
    use tempfile::NamedTempFile;

    let svg = get_badge_svg_inner(client_id, name, width, height, font_size, style, "png")?;

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
