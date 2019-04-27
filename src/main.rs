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
use rocket_contrib::json::JsonValue;
use rocket_cors;
use rocket_cors::{AllowedHeaders, AllowedOrigins, Error};

//  type Buf = Buffer<AddOrigin<Connection<TcpStream, DefaultExecutor, BoxBody>>, http::Request<BoxBody>>;
//  type RolodexClient = client::RolodexService<Buf>;

mod certs;
mod config;
mod rolodex_client;

#[derive(Debug, Responder)]
#[response(status = 500, content_type = "json")]
pub struct ResponseError {
    response: content::Json<String>,
}

#[derive(Debug, Responder)]
#[response(status = 404, content_type = "json")]
pub struct ResponseNone {
    response: content::Json<String>,
}

#[derive(Debug, Responder)]
#[response(status = 400, content_type = "json")]
pub struct ResponseBadRequest {
    response: content::Json<String>,
}

#[get("/")]
fn hello() -> Result<content::Json<String>, ResponseError> {
    use rolodex_grpc::proto::*;
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);
    let result = rolodex_client.add_user(NewUserRequest {
        full_name: "What is in a name?".to_string(),
        email: "hey poo".to_string(),
        password_hash: "123".to_string(),
        phone_number: Some(PhoneNumber {
            country: "US".into(),
            number: "123".into(),
        }),
    });
    match result {
        Ok(resp) => match resp.result {
            Some(result) => match result {
                new_user_response::Result::UserId(user_id) => Ok(content::Json(
                    json!({
                        "user_id":user_id.clone(),
                    })
                    .to_string(),
                )),
                new_user_response::Result::Error(err) => Ok(content::Json(
                    json!({
                        "error":err,
                    })
                    .to_string(),
                )),
            },
            None => Err(ResponseError {
                response: content::Json(
                    json!({
                        "error": "Unauthorized"
                    })
                    .to_string(),
                ),
            }),
        },
        Err(err) => Err(ResponseError {
            response: content::Json(json!({ "error": err.to_string() }).to_string()),
        }),
    }
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

fn main() -> Result<(), Error> {
    config::load_config();

    let cors = rocket_cors::Cors {
        allowed_origins: AllowedOrigins::all(),
        allowed_headers: AllowedHeaders::all(),
        allow_credentials: true,
        ..Default::default()
    };

    rocket::ignite()
        .attach(cors)
        .register(catchers![not_found, unprocessable_entity])
        .mount("/", routes![hello])
        .launch();

    Ok(())
}
