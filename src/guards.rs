use crate::config;
use crate::fairings::{RedisReader, RedisWriter};
use crate::token;
use rocket::http::Status;
use rocket::Outcome;

#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
}

impl<'a, 'r> rocket::request::FromRequest<'a, 'r> for Client {
    type Error = ();

    fn from_request(
        request: &'a rocket::request::Request<'r>,
    ) -> rocket::request::Outcome<Client, Self::Error> {
        use rocket_contrib::databases::redis::Commands;

        // Store the client object in local request cache to avoid multiple lookups
        let client = request.local_cache(|| {
            let redis_reader = request.guard::<RedisReader>().unwrap();
            let redis = &*redis_reader;

            request
                .cookies()
                .get("X-UMPYRE-APIKEY")
                .and_then(|cookie| Some(cookie.value())) // API key can come from a cookie (preferred), or
                .or_else(|| request.headers().get_one("X-UMPYRE-APIKEY")) // from headers
                .map(std::string::ToString::to_string)
                .and_then(|token: String| match token::decode_into_sub(&token) {
                    Ok(client_id) => Some((token, client_id)),
                    Err(_) => None,
                })
                .and_then(|(token, client_id)| {
                    let is_member: bool = redis
                        .sismember(&format!("token:{}", client_id), token)
                        .unwrap();
                    if is_member {
                        Some(Client { client_id })
                    } else {
                        None
                    }
                })
        });

        match client {
            Some(client) => Outcome::Success(client.clone()),
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
            // 1. Client ID
            // 2. X-Forwarded-For
            // 3. Client IP from request
            let key = match request.guard::<Client>().succeeded() {
                Some(client) => vec![client.client_id],
                None => request
                    .headers()
                    .get_one("X-Forwarded-For")
                    .map(|s| {
                        info!("X-Forwarded-For: {:?}", s);

                        s.split(',')
                            .map(str::trim)
                            .map(std::string::ToString::to_string)
                            .collect()
                    })
                    .or_else(|| Some(vec![]))
                    .unwrap(),
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
                // That _should_ give us the client IP address.
                format!("throttle:{}", key[key.len() - 2])
            };

            info!("key={:?}", key);

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
        let rate_limited = ratelimit_from_request(&config::CONFIG.rate_limits.private, request);
        if !rate_limited.limited {
            Outcome::Success(RateLimitedPrivate { rate_limited })
        } else {
            Outcome::Failure((Status::TooManyRequests, ()))
        }
    }
}

#[derive(Debug, Clone)]
pub struct GeoHeaders {
    pub region: String,
    pub region_subdivision: String,
    pub city: String,
}

impl<'a, 'r> rocket::request::FromRequest<'a, 'r> for GeoHeaders {
    type Error = ();

    fn from_request(
        request: &'a rocket::request::Request<'r>,
    ) -> rocket::request::Outcome<GeoHeaders, Self::Error> {
        // Format is:
        // "X-Client-Geo-Location: {client_region},{client_region_subdivision},{client_city}"
        if let Some(value) = request.headers().get_one("X-Client-Geo-Location") {
            let values: Vec<&str> = value.split(',').collect();
            info!("X-Client-Geo-Location: {:?}", values);
            if values.len() == 3 {
                Outcome::Success(GeoHeaders {
                    region: values[0].into(),
                    region_subdivision: values[1].into(),
                    city: values[2].into(),
                })
            } else {
                Outcome::Forward(())
            }
        } else {
            Outcome::Forward(())
        }
    }
}
