use crate::config;
use crate::fairings::{RedisReader, RedisWriter};
use crate::token;
use rocket::http::Status;
use rocket::Outcome;

trait MakeClient {
    fn make_client(client_id: String) -> Self;
}

fn get_auth_client<'a, 'r, C: MakeClient + Send + Sync + Clone + 'static>(
    token_name: &str,
    request: &'a rocket::request::Request<'r>,
) -> rocket::request::Outcome<C, ()> {
    use rocket_contrib::databases::redis::Commands;

    // Store the client object in local request cache to avoid multiple lookups
    let client = request.local_cache(|| {
        let redis_reader = request.guard::<RedisReader>().unwrap();
        let redis = &*redis_reader;

        request
            .cookies()
            .get(token_name)
            .and_then(|cookie| Some(cookie.value())) // API key can come from a cookie (preferred), or
            .or_else(|| request.headers().get_one(token_name)) // from headers
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
                    Some(C::make_client(client_id))
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

#[derive(Debug, Clone)]
pub struct Client {
    pub client_id: String,
}

impl MakeClient for Client {
    fn make_client(client_id: String) -> Self {
        Client { client_id }
    }
}

impl<'a, 'r> rocket::request::FromRequest<'a, 'r> for Client {
    type Error = ();

    fn from_request(
        request: &'a rocket::request::Request<'r>,
    ) -> rocket::request::Outcome<Client, Self::Error> {
        get_auth_client("X-UMPYRE-APIKEY", request)
    }
}

#[derive(Debug, Clone)]
pub struct TempClient {
    pub client_id: String,
}

impl MakeClient for TempClient {
    fn make_client(client_id: String) -> Self {
        TempClient { client_id }
    }
}

impl<'a, 'r> rocket::request::FromRequest<'a, 'r> for TempClient {
    type Error = ();

    fn from_request(
        request: &'a rocket::request::Request<'r>,
    ) -> rocket::request::Outcome<TempClient, Self::Error> {
        get_auth_client("X-UMPYRE-APIKEY-TEMP", request)
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
                Some(client) => client.client_id,
                None => match request.guard::<ClientIP>().succeeded() {
                    Some(client_ip) => client_ip.0,
                    None => "none".to_string(),
                },
            };

            trace!("throttle key={:?}", key);
            format!("throttle:{}", key);

            let (limited, limit, remaining, retry_after, reset): (i32, i32, i32, i32, i32) =
                redis::cmd("CL.THROTTLE")
                    .arg(&key)
                    .arg(config.max_burst)
                    .arg(config.tokens)
                    .arg(config.period)
                    .query(redis)
                    .unwrap();

            let limited = limited == 1;

            if limited {
                info!("Request from {} being rate limited: limit={} remaining={} retry_after={} reset={}",
                key,
                limit, remaining, retry_after, reset);
            }

            RateLimited {
                key,
                limited,
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

#[derive(Debug, Clone)]
pub struct ClientIP(pub String);

impl<'a, 'r> rocket::request::FromRequest<'a, 'r> for ClientIP {
    type Error = ();

    fn from_request(
        request: &'a rocket::request::Request<'r>,
    ) -> rocket::request::Outcome<ClientIP, Self::Error> {
        let forwarded_for = request
            .headers()
            .get_one("X-Forwarded-For")
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .map(std::string::ToString::to_string)
                    .collect()
            })
            .or_else(|| Some(vec![]))
            .unwrap();

        if forwarded_for.is_empty() || forwarded_for.len() < 2 {
            let client_ip = request.client_ip().unwrap().to_string();

            Outcome::Success(ClientIP(client_ip.into()))
        } else {
            // Take the second from last value of X-Forwarded-For, as per the docs at:
            // https://cloud.google.com/load-balancing/docs/https/
            // That _should_ give us the client IP address.
            Outcome::Success(ClientIP(forwarded_for[forwarded_for.len() - 2].to_string()))
        }
    }
}
