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

use rocket::http::{Cookie, Cookies};
use rocket::response::content;
use rocket_contrib::json::{Json, JsonValue};

mod certs;
mod config;
mod models;
mod rolodex_client;
mod token;

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

impl From<rolodex_client::RolodexError> for ResponseError {
    fn from(err: rolodex_client::RolodexError) -> Self {
        ResponseError::BadRequest {
            response: content::Json(
                json!({
                    "error": err.to_string(),
                })
                .to_string(),
            ),
        }
    }
}

#[post("/authenticate", data = "<auth_request>", format = "json")]
fn authenticate(
    mut cookies: Cookies,
    redis_writer: RedisWriter,
    auth_request: Json<models::AuthRequest>,
) -> Result<Json<models::AuthResponse>, ResponseError> {
    let rolodex_client = rolodex_client::Client::new(&config::CONFIG);
    let response = rolodex_client.authenticate(rolodex_grpc::proto::AuthRequest {
        user_id: auth_request.user_id.clone(),
        password_hash: auth_request.password_hash.clone(),
    })?;

    match response.result {
        Some(result) => match result {
            rolodex_grpc::proto::auth_response::Result::UserId(user_id) => {
                use rocket_contrib::databases::redis::Commands;

                // generate token (JWT)
                let token = token::generate(&user_id);

                // store token in Redis
                let redis = &*redis_writer;
                let _c: i32 = redis.sadd(&format!("tokens:{}", user_id), &token).unwrap();

                let cookie = Cookie::build("X-UMPYRE-APIKEY", token.clone())
                    .path("/")
                    .secure(true)
                    .permanent()
                    .finish();
                cookies.add(cookie);

                Ok(Json(models::AuthResponse { user_id, token }))
            }
            rolodex_grpc::proto::auth_response::Result::Error(error) => {
                Err(ResponseError::Unauthorized {
                    response: content::Json(
                        json!({
                            "code": error,
                            "error": "invalid credentials".to_string(),
                        })
                        .to_string(),
                    ),
                })
            }
        },
        None => Err(ResponseError::Unauthorized {
            response: content::Json(
                json!({
                    "error": "invalid credentials".to_string(),
                })
                .to_string(),
            ),
        }),
    }
}

#[derive(Serialize)]
struct Hello {
    hi: String,
}

#[derive(Debug, Clone)]
struct User {
    user_id: String,
}

impl<'a, 'r> rocket::request::FromRequest<'a, 'r> for User {
    type Error = ();

    fn from_request(
        request: &'a rocket::request::Request<'r>,
    ) -> rocket::request::Outcome<User, Self::Error> {
        use rocket::http::Status;
        use rocket::outcome::IntoOutcome;
        use rocket_contrib::databases::redis::Commands;

        let redis_reader = request.guard::<RedisReader>().unwrap();
        let redis = &*redis_reader;
        request
            .cookies()
            .get("X-UMPYRE-APIKEY")
            .and_then(|cookie| Some(cookie.value()))
            .or_else(|| request.headers().get_one("X-UMPYRE-APIKEY"))
            .map(std::string::ToString::to_string)
            .and_then(|token: String| match token::decode_into_sub(&token) {
                Ok(user_id) => Some((token, user_id)),
                Err(_) => None,
            })
            .and_then(|(token, user_id)| {
                let is_member: bool = redis
                    .sismember(&format!("token:{}", user_id), token)
                    .unwrap();
                if is_member {
                    Some(User { user_id })
                } else {
                    None
                }
            })
            .into_outcome((Status::Unauthorized, ()))
    }
}

#[get("/hello", format = "json")]
fn hello(user: User) -> Result<Json<Hello>, ResponseError> {
    Ok(Json(Hello {
        hi: user.user_id.clone(),
    }))
}

#[get("/ping")]
fn ping() -> String {
    "pong".into()
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

#[catch(401)]
fn unauthorized() -> JsonValue {
    json!({
        "status": "error",
        "reason": "Unauthorized."
    })
}

#[database("redis_reader")]
struct RedisReader(rocket_contrib::databases::redis::Connection);

#[database("redis_writer")]
struct RedisWriter(rocket_contrib::databases::redis::Connection);

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
        .attach(RedisReader::fairing())
        .attach(RedisWriter::fairing())
        .attach(helmet)
        .attach(cors)
        .attach(Compression::fairing())
        .register(catchers![not_found, unprocessable_entity, unauthorized])
        .mount("/", routes![authenticate, hello, ping])
        .launch();

    Ok(())
}
