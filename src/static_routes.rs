use std::io::Cursor;

use rocket::response::Responder;
use rocket::http::{ContentType, Status};
use rocket::{Response, Request};

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
    fn respond_to(
        self,
        _: &Request,
    ) -> Result<Response<'static>, Status> {
        rocket::Response::build()
            .header(ContentType::HTML)
            .sized_body(Cursor::new(self.body))
            .ok()
    }
}

#[get("/openapi.html")]
pub fn openapi() -> Result<StaticHtml, Status> {
    Ok(include_str!(concat!(env!("OUT_DIR"), "/openapi.html")).into())
}
