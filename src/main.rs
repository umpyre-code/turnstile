#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
extern crate env_logger;
extern crate http;
extern crate instrumented;
extern crate yansi;
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate validator_derive;
extern crate validator;

mod catchers;
mod certs;
mod config;
mod fairings;
mod guards;
mod models;
mod rolodex_client;
mod routes;
mod token;

fn main() -> Result<(), std::io::Error> {
    use rocket::http::uri::Uri;
    use rocket_contrib::compression::Compression;
    use rocket_contrib::helmet::{Frame, Hsts, Referrer, SpaceHelmet, XssFilter};
    use rocket_cors::{AllowedHeaders, AllowedMethods, AllowedOrigins};
    use std::str::FromStr;

    config::load_config();

    let allowed_methods: AllowedMethods = ["Get", "Post", "Put", "Delete"]
        .iter()
        .map(|s| FromStr::from_str(s).unwrap())
        .collect();

    let cors = rocket_cors::CorsOptions {
        allowed_origins: AllowedOrigins::all(),
        allowed_methods,
        allowed_headers: AllowedHeaders::all(),
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors()
    .unwrap();

    let site_uri = Uri::parse(&config::CONFIG.site_uri).unwrap();
    let report_uri = Uri::parse(&config::CONFIG.site_uri).unwrap();
    let helmet = SpaceHelmet::default()
        .enable(Hsts::default())
        .enable(Frame::AllowFrom(site_uri))
        .enable(XssFilter::EnableReport(report_uri))
        .enable(Referrer::NoReferrer);

    rocket::ignite()
        .attach(fairings::RedisReader::fairing())
        .attach(fairings::RedisWriter::fairing())
        .attach(Compression::fairing())
        .attach(helmet)
        .attach(cors)
        .register(catchers![
            catchers::not_found,
            catchers::unprocessable_entity,
            catchers::unauthorized
        ])
        .mount(
            "/",
            routes![routes::authenticate, routes::hello, routes::ping],
        )
        .launch();

    Ok(())
}
