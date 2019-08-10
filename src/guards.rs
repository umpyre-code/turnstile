use crate::auth;
use crate::config;
use crate::fairings::{RedisReader, RedisWriter};
use rocket::http::Status;
use rocket::Outcome;

trait MakeClient {
    fn make_client(client_id: String) -> Self;
}

fn get_auth_client<'a, 'r, C: MakeClient + Send + Sync + Clone + 'static>(
    token_name: &str,
    request: &'a rocket::request::Request<'r>,
) -> rocket::request::Outcome<C, ()> {
    // Store the client object in local request cache to avoid multiple lookups
    let client = request.local_cache(|| {
        let mut redis_reader = request.guard::<RedisReader>().unwrap();

        request
            .headers()
            .get_one(token_name) // API key comes from headers
            .map(std::string::ToString::to_string)
            .and_then(|token: String| {
                if let Ok(client_id) = auth::verify_auth_token_get_sub(&mut *redis_reader, &token) {
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
        get_auth_client("X-UMPYRE-TOKEN", request)
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
        get_auth_client("X-UMPYRE-TOKEN-TEMP", request)
    }
}

#[derive(Debug, Clone, Default)]
pub struct RateLimit {
    pub key: String,
    pub limited: bool,
    pub limit: i32,
    pub remaining: i32,
    pub retry_after: i32,
    pub reset: i32,
}

#[derive(Debug, Clone, Default)]
pub struct RateLimited {
    pub rate_limit: RateLimit,
}

fn ratelimit_from_request<'a, 'r>(request: &'a rocket::request::Request<'r>) -> RateLimit {
    use crate::redis::db::{redis, RedisResult};
    use std::str::FromStr;

    request
        .local_cache(|| {
            let mut redis_writer = request.guard::<RedisWriter>().unwrap();
            let redis = &mut *redis_writer;

            let client = request.guard::<Client>();

            let ratelimit_config = if client.as_ref().succeeded().is_some() {
                // use private rate limit
                &config::CONFIG.rate_limits.private
            } else {
                // use public rate limit
                &config::CONFIG.rate_limits.public
            };

            // Prefer:
            // 1. Client ID
            // 2. X-Forwarded-For
            // 3. Client IP from request
            let key = match client.succeeded() {
                Some(client) => client.client_id,
                None => match request.guard::<ClientIP>().succeeded() {
                    Some(client_ip) => client_ip.0,
                    None => "none".to_string(),
                },
            };

            // Whitelist private IPs
            if let Ok(addr) = std::net::Ipv4Addr::from_str(&key) {
                if addr.is_private() {
                    // If this is a private address, ignore it. It's probably a health check.
                    return RateLimit {
                        key,
                        limited: false,
                        limit: 0, remaining: 0, retry_after:0, reset:0,
                    };
                }
            }

            trace!("throttle key={:?}", key);
            let key = format!("throttle:{}", key);

            let result: RedisResult<(i32, i32, i32, i32, i32)> =
                redis::cmd("CL.THROTTLE")
                    .arg(&key)
                    .arg(ratelimit_config.max_burst)
                    .arg(ratelimit_config.tokens)
                    .arg(ratelimit_config.period)
                    .query(&mut redis.0);

            match result {
                Ok((limited, limit, remaining, retry_after, reset)) =>{
                    let limited = limited == 1;
                    if limited {
                        info!("Request from {} being rate limited: limit={} remaining={} retry_after={} reset={}",
                        key,
                        limit, remaining, retry_after, reset);
                    }

                    RateLimit {
                        key,
                        limited,
                        limit,
                        remaining,
                        retry_after,
                        reset,
                    }
                },
                Err(err) => {
                    error!("redis error: {:?}", err);
                    RateLimit {
                        key,
                        limited: false,
                        limit: 0,
                        remaining: 0,
                        retry_after: 0,
                        reset: 0,
                    }
                }
            }
        })
        .clone()
}

impl<'a, 'r> rocket::request::FromRequest<'a, 'r> for RateLimited {
    type Error = ();

    fn from_request(
        request: &'a rocket::request::Request<'r>,
    ) -> rocket::request::Outcome<RateLimited, Self::Error> {
        let rate_limit = ratelimit_from_request(request);
        if !rate_limit.limited {
            Outcome::Success(RateLimited { rate_limit })
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

            Outcome::Success(ClientIP(client_ip))
        } else {
            // Take the second from last value of X-Forwarded-For, as per the docs at:
            // https://cloud.google.com/load-balancing/docs/https/
            // That _should_ give us the client IP address.
            Outcome::Success(ClientIP(forwarded_for[forwarded_for.len() - 2].to_string()))
        }
    }
}
