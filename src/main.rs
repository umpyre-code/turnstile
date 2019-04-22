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
extern crate yansi;
#[macro_use]
extern crate log;

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

#[get("/")]
fn hello() -> Result<content::Json<String>, ResponseError> {
    rolodex_client::run();
    Ok(content::Json(json!({"hey":"hey"}).to_string()))
}

// #[get("/meals")] // GET /v1/meals
// fn list(conn: DbConn) -> Result<content::Json<String>, ResponseError> {
//     use diesel::prelude::*;
//     use schema::meals::dsl::*;

//     let query_result = meals.load::<Meal>(&*conn);

//     match query_result {
//         Ok(results) => Ok(content::Json(json!(results).to_string())),
//         Err(error) => Err(ResponseError {
//             response: content::Json(json!({ "error": error.to_string() }).to_string()),
//         }),
//     }
// }

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
