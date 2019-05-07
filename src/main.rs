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

mod catchers;
mod certs;
mod config;
mod fairings;
mod guards;
mod models;
mod rolodex_client;
mod routes;
mod token;

fn get_cors() -> rocket_cors::Cors {
    use rocket_cors::{AllowedHeaders, AllowedMethods, AllowedOrigins};
    use std::str::FromStr;

    let allowed_methods: AllowedMethods = ["Get", "Post", "Put", "Delete"]
        .iter()
        .map(|s| FromStr::from_str(s).unwrap())
        .collect();

    rocket_cors::CorsOptions {
        allowed_origins: AllowedOrigins::all(),
        allowed_methods,
        allowed_headers: AllowedHeaders::all(),
        allow_credentials: true,
        ..Default::default()
    }
    .to_cors()
    .unwrap()
}

fn get_helmet() -> rocket_contrib::helmet::SpaceHelmet {
    use rocket::http::uri::Uri;
    use rocket_contrib::helmet::{Frame, Hsts, Referrer, SpaceHelmet, XssFilter};
    let site_uri = Uri::parse(&config::CONFIG.service.site_uri).unwrap();
    let report_uri = Uri::parse(&config::CONFIG.service.site_uri).unwrap();

    SpaceHelmet::default()
        .enable(Hsts::default())
        .enable(Frame::AllowFrom(site_uri))
        .enable(XssFilter::EnableReport(report_uri))
        .enable(Referrer::NoReferrer)
}

fn main() -> Result<(), std::io::Error> {
    use rocket_contrib::compression::Compression;
    use std::env;

    ::env_logger::init();

    config::load_config();

    // Allow disablement of metrics reporting for testing
    if env::var_os("DISABLE_INSTRUMENTED").is_none() {
        instrumented::init(&config::CONFIG.metrics.bind_to_address);
    }

    rocket::ignite()
        .attach(fairings::RequestTimer)
        .attach(fairings::Counter)
        .attach(fairings::RateLimitHeaders)
        .attach(fairings::RedisReader::fairing())
        .attach(fairings::RedisWriter::fairing())
        .attach(Compression::fairing())
        .attach(get_helmet())
        .attach(get_cors())
        .register(catchers![
            catchers::bad_request,
            catchers::not_found,
            catchers::too_many_requests,
            catchers::unauthorized,
            catchers::unprocessable_entity,
        ])
        .mount(
            "/",
            routes![
                routes::get_ping,
                routes::get_user,
                routes::post_user_authenticate,
                routes::post_user,
            ],
        )
        .launch();

    Ok(())
}
