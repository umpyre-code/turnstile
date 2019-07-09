use crate::error::ResponseError;
use crate::fairings;
use crate::token;

use rocket::http::{Cookie, Cookies};

pub fn handle_auth_token(
    mut cookies: Cookies,
    redis_writer: fairings::RedisWriter,
    client_id: &str,
) -> Result<String, ResponseError> {
    use rocket_contrib::databases::redis::Commands;
    use time::Duration;

    // 1 year expiry
    let expiry = 365 * 24 * 3600;

    // generate token (JWT)
    let token = token::generate(&client_id, expiry);

    // store token in Redis
    let redis = &*redis_writer;
    let _c: i32 = redis.sadd(&format!("token:{}", client_id), &token)?;

    let cookie = Cookie::build("X-UMPYRE-APIKEY", token.clone())
        .path("/")
        .secure(true)
        .max_age(Duration::seconds(expiry as i64))
        .finish();
    cookies.add(cookie);

    Ok(token)
}

pub fn handle_auth_temporary_token(
    mut cookies: Cookies,
    redis_writer: fairings::RedisWriter,
    client_id: &str,
) -> Result<String, ResponseError> {
    use rocket_contrib::databases::redis::Commands;
    use time::Duration;

    // 1 hour expiry
    let expiry = 3600;

    // generate token (JWT)
    let token = token::generate(&client_id, expiry);

    // store token in Redis
    let redis = &*redis_writer;
    let _c: i32 = redis.sadd(&format!("token:{}", client_id), &token)?;

    let cookie = Cookie::build("X-UMPYRE-APIKEY-TEMP", token.clone())
        .path("/")
        .secure(true)
        .max_age(Duration::seconds(expiry as i64))
        .finish();
    cookies.add(cookie);

    Ok(token)
}
