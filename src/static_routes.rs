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
pub fn openapi() -> Result<StaticHtml, Status> {
    Ok(include_str!(concat!(env!("OUT_DIR"), "/openapi.html")).into())
}
