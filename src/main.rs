#![feature(proc_macro_hygiene, decl_macro, try_trait)]

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

extern crate chrono;
extern crate rand;
extern crate time;
extern crate uuid;

mod auth;
mod beancounter_client;
mod catchers;
mod config;
mod error;
mod fairings;
mod guards;
mod models;
mod optional;
mod responders;
mod rolodex_client;
mod routes;
mod static_routes;
mod switchroom_client;
mod token;
mod utils;

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
        max_age: Some(3600 * 24), // Cache for 24h
        ..Default::default()
    }
    .to_cors()
    .unwrap()
}

fn get_helmet() -> rocket_contrib::helmet::SpaceHelmet {
    use rocket::http::uri::Uri;
    use rocket_contrib::helmet::{ExpectCt, Frame, Hsts, Referrer, SpaceHelmet, XssFilter};
    use time::Duration;
    let site_uri = Uri::parse(&config::CONFIG.service.site_uri).unwrap();
    let report_uri = Uri::parse(&config::CONFIG.service.site_uri).unwrap();

    let helmet = SpaceHelmet::default()
        .enable(Hsts::default())
        .enable(Frame::AllowFrom(site_uri))
        .enable(XssFilter::EnableReport(report_uri))
        .enable(ExpectCt::Enforce(Duration::weeks(52)))
        .enable(Referrer::NoReferrer);

    if config::CONFIG.service.enable_hsts {
        // Enable HSTS for 1 year
        helmet.enable(Hsts::IncludeSubDomains(Duration::weeks(52)))
    } else {
        helmet
    }
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
                routes::get_account_balance,
                routes::get_account_connect,
                routes::get_client_by_handle,
                routes::get_client,
                routes::get_messages,
                routes::get_ping,
                routes::post_account_connect_payout,
                routes::post_account_connect_prefs,
                routes::post_account_oauth,
                routes::post_client_auth_handshake_temporarily,
                routes::post_client_auth_handshake,
                routes::post_client_auth_verify_temporarily,
                routes::post_client_auth_verify,
                routes::post_client,
                routes::post_messages,
                routes::post_stripe_charge,
                routes::put_client,
                routes::put_messages_settle,
                static_routes::openapi_html,
                static_routes::openapi_yaml,
            ],
        )
        .launch();

    Ok(())
}
