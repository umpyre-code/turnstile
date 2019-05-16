use std::io::Cursor;

use rocket::http::hyper::header::{CacheControl, CacheDirective};
use rocket::http::{ContentType, Status};
use rocket::response::Responder;
use rocket::{Request, Response};

pub struct StaticHtml {
    body: String,
}

impl From<&str> for StaticHtml {
    fn from(s: &str) -> Self {
        StaticHtml {
            body: s.to_string(),
        }
    }
}

impl Responder<'static> for StaticHtml {
    fn respond_to(self, _: &Request) -> Result<Response<'static>, Status> {
        rocket::Response::build()
            .header(ContentType::HTML)
            .header(CacheControl(vec![
                CacheDirective::Public,
                CacheDirective::MaxAge(3600u32),
            ]))
            .sized_body(Cursor::new(self.body))
            .ok()
    }
}

#[get("/openapi.html")]
pub fn openapi_html() -> Result<StaticHtml, Status> {
    Ok(include_str!(concat!(env!("OUT_DIR"), "/openapi.html")).into())
}

pub struct StaticYaml {
    body: String,
}

impl From<&str> for StaticYaml {
    fn from(s: &str) -> Self {
        StaticYaml {
            body: s.to_string(),
        }
    }
}

impl Responder<'static> for StaticYaml {
    fn respond_to(self, _: &Request) -> Result<Response<'static>, Status> {
        rocket::Response::build()
            .header(ContentType::new("application", "x-yaml"))
            .header(CacheControl(vec![
                CacheDirective::Public,
                CacheDirective::MaxAge(3600u32),
            ]))
            .sized_body(Cursor::new(self.body))
            .ok()
    }
}

#[get("/openapi.yaml")]
pub fn openapi_yaml() -> Result<StaticYaml, Status> {
    Ok(include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml")).into())
}
