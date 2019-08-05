use std::time::Instant;

use instrumented::{prometheus, register};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::{Data, Request, Response};

use crate::beancounter_client;
use crate::rolodex_client;
use crate::switchroom_client;

lazy_static! {
    static ref REQUEST_COUNTER: prometheus::IntCounterVec = {
        let counter_opts = prometheus::Opts::new("http_requests", "HTTP Request counter");
        let counter = prometheus::IntCounterVec::new(counter_opts, &["method"]).unwrap();
        register(Box::new(counter.clone())).unwrap();
        counter
    };
    static ref RESPONSE_COUNTER: prometheus::IntCounterVec = {
        let counter_opts = prometheus::Opts::new("http_responses", "HTTP Request counter");
        let counter =
            prometheus::IntCounterVec::new(counter_opts, &["route", "method", "code"]).unwrap();
        register(Box::new(counter.clone())).unwrap();
        counter
    };
    static ref HANDLER_TIMER: prometheus::HistogramVec = {
        let histogram_opts = prometheus::HistogramOpts::new(
            "request_handler_time",
            "Histogram of handler call times observed in seconds",
        );
        let histogram =
            prometheus::HistogramVec::new(histogram_opts, &["route", "method", "code"]).unwrap();

        register(Box::new(histogram.clone())).unwrap();

        histogram
    };
    static ref RESPONSE_LENGTH: prometheus::HistogramVec = {
        let histogram_opts = prometheus::HistogramOpts::new(
            "http_response_length",
            "Histogram of response length in bytes",
        );
        let histogram =
            prometheus::HistogramVec::new(histogram_opts, &["route", "method", "code"]).unwrap();

        register(Box::new(histogram.clone())).unwrap();

        histogram
    };
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

        let start_time = request.local_cache(|| TimerStart(None));
        if let Some(duration) = start_time.0.map(|s| s.elapsed()) {
            let us = duration.as_secs() * 1_000_000 + u64::from(duration.subsec_micros());
            let s = (us as f64) / 1_000_000.0;

            HANDLER_TIMER
                .with_label_values(&[
                    route,
                    request.method().as_str(),
                    &format!("{}", response.status().code),
                ])
                .observe(s);
        }

        if let Some(rocket::response::Body::Sized(_, size)) = response.body() {
            RESPONSE_LENGTH
                .with_label_values(&[
                    route,
                    request.method().as_str(),
                    &format!("{}", response.status().code),
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
        REQUEST_COUNTER
            .with_label_values(&[request.method().as_str()])
            .inc();
    }

    fn on_response(&self, request: &Request, response: &mut Response) {
        let route = if let Some(route) = request.route() {
            route.uri.path()
        } else {
            "none"
        };
        RESPONSE_COUNTER
            .with_label_values(&[
                route,
                request.method().as_str(),
                &format!("{}", response.status().code),
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
pub struct RedisReader(rocket_contrib::databases::redis::Connection);

#[database("redis_writer")]
pub struct RedisWriter(rocket_contrib::databases::redis::Connection);
