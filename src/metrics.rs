use crate::error::ResponseError;
use crate::guards;

use instrumented::{prometheus, register};

lazy_static! {
    static ref METRICS_COUNTER: prometheus::IntCounterVec = {
        let counter_opts = prometheus::Opts::new("metrics_counter_total", "Metrics counter");
        let counter = prometheus::IntCounterVec::new(counter_opts, &["metric"]).unwrap();
        register(Box::new(counter.clone())).unwrap();
        counter
    };
    static ref METRICS_COUNTER_REASON: prometheus::IntCounterVec = {
        let counter_opts = prometheus::Opts::new(
            "metrics_counter_reason_total",
            "Metrics counter with reason",
        );
        let counter = prometheus::IntCounterVec::new(counter_opts, &["metric", "reason"]).unwrap();
        register(Box::new(counter.clone())).unwrap();
        counter
    };
}

#[post("/metrics/counter/<metric>/inc")]
pub fn post_metrics_counter_inc(
    metric: String,
    _ratelimited: guards::RateLimited,
) -> Result<(), ResponseError> {
    METRICS_COUNTER.with_label_values(&[metric.as_str()]).inc();
    Ok(())
}

#[post("/metrics/counter/<metric>/<reason>/inc")]
pub fn post_metrics_counter_reason_inc(
    metric: String,
    reason: String,
    _ratelimited: guards::RateLimited,
) -> Result<(), ResponseError> {
    METRICS_COUNTER_REASON
        .with_label_values(&[metric.as_str(), reason.as_str()])
        .inc();
    Ok(())
}
