use crate::config;
use crate::fairings::{RedisReader, RedisWriter};
use crate::token;

#[derive(Debug, Clone)]
pub struct User {
    pub user_id: String,
}

impl<'a, 'r> rocket::request::FromRequest<'a, 'r> for User {
    type Error = ();

    fn from_request(
        request: &'a rocket::request::Request<'r>,
    ) -> rocket::request::Outcome<User, Self::Error> {
        use rocket::http::Status;
        use rocket::outcome::Outcome;
        use rocket_contrib::databases::redis::Commands;

        // Store the user object in local request cache to avoid multiple lookups
        let user = request.local_cache(|| {
            let redis_reader = request.guard::<RedisReader>().unwrap();
            let redis = &*redis_reader;

            request
                .cookies()
                .get("X-UMPYRE-APIKEY")
                .and_then(|cookie| Some(cookie.value())) // API key can come from a cookie (preferred), or
                .or_else(|| request.headers().get_one("X-UMPYRE-APIKEY")) // from headers
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
        });

        match user {
            Some(user) => Outcome::Success(user.clone()),
            None => Outcome::Failure((Status::Unauthorized, ())),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct RateLimited {
    pub key: String,
    pub limited: bool,
    pub limit: i32,
    pub remaining: i32,
    pub retry_after: i32,
    pub reset: i32,
}

#[derive(Debug, Clone, Default)]
pub struct RateLimitedPublic {
    pub rate_limited: RateLimited,
}

#[derive(Debug, Clone, Default)]
pub struct RateLimitedPrivate {
    pub rate_limited: RateLimited,
}

fn ratelimit_from_request<'a, 'r>(
    config: &config::RateLimit,
    request: &'a rocket::request::Request<'r>,
) -> RateLimited {
    use rocket_contrib::databases::redis;

    request
        .local_cache(|| {
            let redis_writer = request.guard::<RedisWriter>().unwrap();
            let redis = &*redis_writer;

            // Prefer:
            // 1. User ID
            // 2. X-Forwarded-For
            // 3. Client IP from request
            let key = match request.guard::<User>().succeeded() {
                Some(user) => vec![user.user_id],
                None => request
                    .headers()
                    .get("X-Forwarded-For")
                    .map(|s| {
                        info!("X-Forwarded-For: {:?}", s);
                        s.to_string()
                    })
                    .collect(),
            };

            let key = if key.is_empty() {
                info!(
                    "Using request.client_ip() to throttle: {:?}",
                    request.client_ip().unwrap()
                );
                vec![request.client_ip().unwrap().to_string()]
            } else {
                key
            };

            info!("key={:?}", key);

            let key = if key.len() == 1 {
                format!("throttle:{}", key.first().unwrap())
            } else {
                // Take the second from last value of X-Forwarded-For, as per the docs at:
                // https://cloud.google.com/load-balancing/docs/https/
                format!("throttle:{}", key[key.len() - 2])
            };

            let (limited, limit, remaining, retry_after, reset): (i32, i32, i32, i32, i32) =
                redis::cmd("CL.THROTTLE")
                    .arg(&key)
                    .arg(config.max_burst)
                    .arg(config.tokens)
                    .arg(config.period)
                    .query(redis)
                    .unwrap();

            RateLimited {
                key,
                limited: limited == 1,
                limit,
                remaining,
                retry_after,
                reset,
            }
        })
        .clone()
}

impl<'a, 'r> rocket::request::FromRequest<'a, 'r> for RateLimitedPublic {
    type Error = ();

    fn from_request(
        request: &'a rocket::request::Request<'r>,
    ) -> rocket::request::Outcome<RateLimitedPublic, Self::Error> {
        use rocket::http::Status;
        use rocket::Outcome;
        let rate_limited = ratelimit_from_request(&config::CONFIG.rate_limits.public, request);
        if !rate_limited.limited {
            Outcome::Success(RateLimitedPublic { rate_limited })
        } else {
            Outcome::Failure((Status::TooManyRequests, ()))
        }
    }
}

impl<'a, 'r> rocket::request::FromRequest<'a, 'r> for RateLimitedPrivate {
    type Error = ();

    fn from_request(
        request: &'a rocket::request::Request<'r>,
    ) -> rocket::request::Outcome<RateLimitedPrivate, Self::Error> {
        use rocket::http::Status;
        use rocket::Outcome;
        let rate_limited = ratelimit_from_request(&config::CONFIG.rate_limits.private, request);
        if !rate_limited.limited {
            Outcome::Success(RateLimitedPrivate { rate_limited })
        } else {
            Outcome::Failure((Status::TooManyRequests, ()))
        }
    }
}
