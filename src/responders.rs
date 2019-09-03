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

#[derive(Debug)]
pub struct Cached<T> {
    pub value: T,
    pub age: u32,
}

impl<T> Cached<T> {
    pub fn from(value: T, age: u32) -> Self {
        Self { value, age }
    }
}

impl<'a, T: Responder<'a>> Responder<'a> for Cached<T> {
    fn respond_to(self, req: &Request) -> rocket::response::Result<'a> {
        Response::build_from(self.value.respond_to(req)?)
            .header(CacheControl(vec![
                CacheDirective::Public,
                CacheDirective::MaxAge(self.age),
            ]))
            .ok()
    }
}

#[derive(Responder)]
#[response(content_type = "image/png")]
pub struct Png(pub Vec<u8>);

#[derive(Responder)]
#[response(content_type = "image/svg+xml")]
pub struct Svg(pub String);

#[derive(Responder)]
#[response(content_type = "image/jpeg")]
pub struct Jpeg(pub String);

#[derive(Responder)]
#[response(content_type = "image/webp")]
pub struct Webp(pub String);
