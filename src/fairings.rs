use std::time::Instant;

use instrumented::{prometheus, register};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Data, Request, Response};

lazy_static! {
    static ref REQUEST_COUNTER: prometheus::IntCounterVec = {
        let counter_opts = prometheus::Opts::new("http_requests_total", "HTTP Request counter");
        let counter = prometheus::IntCounterVec::new(
            counter_opts,
            &["method", "browser_name", "browser_os", "browser_version"],
        )
        .unwrap();
        register(Box::new(counter.clone())).unwrap();
        counter
    };
    static ref RESPONSE_COUNTER: prometheus::IntCounterVec = {
        let counter_opts = prometheus::Opts::new("http_responses_total", "HTTP Request counter");
        let counter = prometheus::IntCounterVec::new(
            counter_opts,
            &[
                "route",
                "method",
                "code",
                "browser_name",
                "browser_os",
                "browser_version",
            ],
        )
        .unwrap();
        register(Box::new(counter.clone())).unwrap();
        counter
    };
    static ref HANDLER_TIMER: prometheus::HistogramVec = {
        let histogram_opts = prometheus::HistogramOpts::new(
            "request_handler_time_seconds",
            "Histogram of handler call times observed in seconds",
        );
        let histogram = prometheus::HistogramVec::new(
            histogram_opts,
            &[
                "route",
                "method",
                "code",
                "browser_name",
                "browser_os",
                "browser_version",
            ],
        )
        .unwrap();

        register(Box::new(histogram.clone())).unwrap();

        histogram
    };
    static ref RESPONSE_LENGTH: prometheus::HistogramVec = {
        let histogram_opts = prometheus::HistogramOpts::new(
            "http_response_bytes",
            "Histogram of response length in bytes",
        );
        let histogram = prometheus::HistogramVec::new(
            histogram_opts,
            &[
                "route",
                "method",
                "code",
                "browser_name",
                "browser_os",
                "browser_version",
            ],
        )
        .unwrap();

        register(Box::new(histogram.clone())).unwrap();

        histogram
    };
}

fn get_ua<'a>(request: &'a Request) -> (&'a str, &'a str, &'a str) {
    use woothee::parser::Parser;
    let ua_string = request
        .headers()
        .get_one("User-Agent")
        .unwrap_or_else(|| "");
    let ua = Parser::new().parse(ua_string);
    match ua {
        Some(ua) => (ua.name, ua.os, ua.version),
        None => ("UNKNOWN", "UNKNOWN", "UNKNOWN"),
    }
}

/// Fairing for timing requests.
pub struct RequestTimer;

/// Value stored in request-local state.
#[derive(Copy, Clone)]
struct TimerStart(Option<Instant>);

impl Fairing for RequestTimer {
    fn info(&self) -> Info {
        Info {
            name: "Request Timer",
            kind: Kind::Request | Kind::Response,
        }
    }

    /// Stores the start time of the request in request-local state.
    fn on_request(&self, request: &mut Request, _: &Data) {
        request.local_cache(|| TimerStart(Some(Instant::now())));
    }

    /// Adds a header to the response indicating how long the server took to
    /// process the request.
    fn on_response(&self, request: &Request, response: &mut Response) {
        let route = if let Some(route) = request.route() {
            route.uri.path()
        } else {
            "none"
        };

        let (browser_name, browser_os, browser_version) = get_ua(request);

        let start_time = request.local_cache(|| TimerStart(None));
        if let Some(duration) = start_time.0.map(|s| s.elapsed()) {
            let us = duration.as_secs() * 1_000_000 + u64::from(duration.subsec_micros());
            let s = (us as f64) / 1_000_000.0;

            HANDLER_TIMER
                .with_label_values(&[
                    route,
                    request.method().as_str(),
                    &format!("{}", response.status().code),
                    browser_name,
                    browser_os,
                    browser_version,
                ])
                .observe(s);
        }

        if let Some(rocket::response::Body::Sized(_, size)) = response.body() {
            RESPONSE_LENGTH
                .with_label_values(&[
                    route,
                    request.method().as_str(),
                    &format!("{}", response.status().code),
                    browser_name,
                    browser_os,
                    browser_version,
                ])
                .observe(size as f64);
        }
    }
}

/// Fairing for request/response counters.
pub struct Counter;

impl Fairing for Counter {
    fn info(&self) -> Info {
        Info {
            name: "Request/response Counter",
            kind: Kind::Request | Kind::Response,
        }
    }

    fn on_request(&self, request: &mut Request, _: &Data) {
        let (browser_name, browser_os, browser_version) = get_ua(request);

        REQUEST_COUNTER
            .with_label_values(&[
                request.method().as_str(),
                browser_name,
                browser_os,
                browser_version,
            ])
            .inc();
    }

    fn on_response(&self, request: &Request, response: &mut Response) {
        let route = if let Some(route) = request.route() {
            route.uri.path()
        } else {
            "none"
        };

        let (browser_name, browser_os, browser_version) = get_ua(request);

        RESPONSE_COUNTER
            .with_label_values(&[
                route,
                request.method().as_str(),
                &format!("{}", response.status().code),
                browser_name,
                browser_os,
                browser_version,
            ])
            .inc();
    }
}

/// Fairing for setting rate limit response headers.
pub struct RateLimitHeaders;

impl Fairing for RateLimitHeaders {
    fn info(&self) -> Info {
        Info {
            name: "Rate limit response headers",
            kind: Kind::Response,
        }
    }

    fn on_response(&self, request: &Request, response: &mut Response) {
        use crate::guards;
        let rate_limit = request.local_cache(guards::RateLimit::default);
        if rate_limit.limit > 0 {
            response.set_raw_header("X-RateLimit-Limit", rate_limit.limit.to_string());
            response.set_raw_header("X-RateLimit-Remaining", rate_limit.remaining.to_string());
            response.set_raw_header("X-RateLimit-Reset", rate_limit.reset.to_string());
            if rate_limit.retry_after >= 0 {
                response.set_raw_header("Retry-After", rate_limit.retry_after.to_string());
            }
        }
    }
}

#[database("redis_reader")]
pub struct RedisReader(crate::redis::db::ReaderConnection);

#[database("redis_writer")]
pub struct RedisWriter(crate::redis::db::WriterConnection);
