#![feature(proc_macro_hygiene, decl_macro, try_trait)]

#[macro_use]
extern crate elastic_derive;
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;

extern crate chrono;
extern crate elastic;
extern crate env_logger;
extern crate http;
extern crate image;
extern crate instrumented;
extern crate libc;
extern crate r2d2_redis_cluster;
extern crate rand;
extern crate rayon;
extern crate reqwest;
extern crate resvg;
extern crate tera;
extern crate time;
extern crate uuid;
extern crate yansi;
extern crate yup_oauth2;

mod auth;
mod beancounter_client;
mod catchers;
mod config;
mod elasticsearch;
mod error;
mod fairings;
mod gcp;
mod guards;
mod images;
mod mailgun;
mod message;
mod metrics;
mod models;
mod optional;
mod redis;
mod responders;
mod rolodex_client;
mod routes;
mod static_routes;
mod switchroom_client;
mod templated;
mod token;
mod utils;

fn get_cors() -> rocket_cors::Cors {
    rocket_cors::CorsOptions {
        allow_credentials: true,
        max_age: Some(3600), // Cache for 1h
        ..Default::default()
    }
    .to_cors()
    .unwrap()
}

fn get_helmet() -> rocket_contrib::helmet::SpaceHelmet {
    use rocket::http::uri::Uri;
    use rocket_contrib::helmet::{ExpectCt, Frame, Hsts, Referrer, SpaceHelmet, XssFilter};
    use time::Duration;
    let web_uri = Uri::parse(&config::CONFIG.service.web_uri).unwrap();
    let report_uri = Uri::parse(&config::CONFIG.service.site_uri).unwrap();

    let helmet = SpaceHelmet::default()
        .enable(Hsts::default())
        .enable(Frame::AllowFrom(web_uri))
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

    // Create elasticsearch indexes if needed
    let elastic_client = elasticsearch::ElasticSearchClient::new();
    elastic_client.create_indices();

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
                images::get_client_image,
                images::post_client_image,
                metrics::post_metrics_counter_inc,
                metrics::post_metrics_counter_reason_inc,
                routes::get_account_balance,
                routes::get_account_connect,
                routes::get_account_transactions,
                routes::get_client_by_handle,
                routes::get_client_prefs,
                routes::get_client,
                routes::get_messages,
                routes::get_ping,
                routes::get_referrals,
                routes::get_stats,
                routes::post_account_connect_payout,
                routes::post_account_connect_prefs,
                routes::post_account_oauth,
                routes::post_client_auth_handshake_temporarily,
                routes::post_client_auth_handshake,
                routes::post_client_auth_verify_temporarily,
                routes::post_client_auth_verify,
                routes::post_client_search,
                routes::post_client_verify_phone_new_code,
                routes::post_client_verify_phone,
                routes::post_client,
                routes::post_messages,
                routes::post_stripe_charge,
                routes::put_client_prefs,
                routes::put_client,
                routes::put_messages_settle,
                static_routes::openapi_html,
                static_routes::openapi_yaml,
                templated::get_badge_png,
                templated::get_badge_svg,
            ],
        )
        .launch();

    Ok(())
}
