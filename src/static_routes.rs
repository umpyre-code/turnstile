use rocket::http::Status;

use crate::responders::{StaticHtml, StaticYaml};

#[get("/openapi.html")]
pub fn openapi_html() -> Result<StaticHtml, Status> {
    Ok(include_str!(concat!(env!("OUT_DIR"), "/openapi.html")).into())
}

#[get("/openapi.yaml")]
pub fn openapi_yaml() -> Result<StaticYaml, Status> {
    Ok(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml")).into())
}
