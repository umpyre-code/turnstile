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

use rocket::response::content;
use rocket_contrib::json::{Json, JsonValue};

//  type Buf = Buffer<AddOrigin<Connection<TcpStream, DefaultExecutor, BoxBody>>, http::Request<BoxBody>>;
//  type RolodexClient = client::RolodexService<Buf>;

mod certs;
mod config;
mod rolodex_client;

#[derive(Responder, Debug)]
enum ResponseError {
    #[response(status = 500, content_type = "json")]
    InternalError { response: content::Json<String> },
    #[response(status = 404, content_type = "json")]
    NotFound { response: content::Json<String> },
    #[response(status = 400, content_type = "json")]
    BadRequest { response: content::Json<String> },
    #[response(status = 403, content_type = "json")]
    Unauthorized { response: content::Json<String> },
}

#[derive(Debug, Serialize)]
struct AuthResponse {
    token: String,
}

#[get("/", format = "json")]
fn hello() -> Result<Json<AuthResponse>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);
    let result = rolodex_client.add_user(rolodex_grpc::proto::NewUserRequest {
        full_name: "What is in a name?".to_string(),
        email: "hey poo".to_string(),
        password_hash: "123".to_string(),
        phone_number: Some(rolodex_grpc::proto::PhoneNumber {
            country: "US".into(),
            number: "123".into(),
        }),
    });
    // match result {
    //     Ok(resp) => match resp.result {
    //         Some(result) => match result {
    //             new_user_response::Result::UserId(user_id) => Ok(content::Json(
    //                 json!({
    //                     "user_id":user_id.clone(),
    //                 })
    //                 .to_string(),
    //             )),
    //             new_user_response::Result::Error(err) => Ok(content::Json(
    //                 json!({
    //                     "error":err,
    //                 })
    //                 .to_string(),
    //             )),
    //         },
    //         None => Err(ResponseError::Unauthorized {
    //             response: content::Json(
    //                 json!({
    //                     "error": "Unauthorized"
    //                 })
    //                 .to_string(),
    //             ),
    //         }),
    //     },
    //     Err(err) => Err(ResponseError::InternalError {
    //         response: content::Json(json!({ "error": err.to_string() }).to_string()),
    //     }),
    // }

    Ok(Json(AuthResponse {
        token: "lol".into(),
    }))
}

#[catch(404)]
fn not_found() -> JsonValue {
    json!({
        "status": "error",
        "reason": "Resource was not found."
    })
}

#[catch(422)]
fn unprocessable_entity() -> JsonValue {
    json!({
        "status": "error",
        "reason": "Unprocessable Entity. The request was well-formed but was unable to be followed due to semantic errors."
    })
}

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
        .attach(helmet)
        .attach(cors)
        .attach(Compression::fairing())
        .register(catchers![not_found, unprocessable_entity])
        .mount("/", routes![hello])
        .launch();

    Ok(())
}
