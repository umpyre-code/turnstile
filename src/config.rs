use log::info;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use toml;
use yansi::Paint;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub service: Service,
    pub rolodex: GrpcService,
    pub switchroom: GrpcService,
    pub beancounter: GrpcService,
    pub jwt: Jwt,
    pub metrics: Metrics,
    pub rate_limits: RateLimits,
    pub gcp: Gcp,
    pub elasticsearch: ElasticSearch,
    pub mailgun: Mailgun,
    pub system_account: Account,
}

#[derive(Debug, Deserialize)]
pub struct Account {
    pub client_id: String,
    pub signing_public_key: String,
    pub signing_secret_key: String,
    pub box_public_key: String,
    pub box_secret_key: String,
    pub welcome_promo_amount: i32,
}

#[derive(Debug, Deserialize)]
pub struct Mailgun {
    pub api_key: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct ElasticSearch {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct Gcp {
    pub project: String,
    pub cdn_url_maps: Vec<String>,
    pub cdn_credentials: String,
    pub image_bucket: String,
    pub image_bucket_credentials: String,
}

#[derive(Debug, Deserialize)]
pub struct Service {
    pub site_uri: String,
    pub web_uri: String,
    pub enable_hsts: bool,
}

#[derive(Debug, Deserialize)]
pub struct GrpcService {
    pub host: String,
    pub port: i32,
    pub ca_cert_path: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
}

#[derive(Debug, Deserialize)]
pub struct Jwt {
    pub iss: String,
    pub leeway: i64,
}

#[derive(Debug, Deserialize)]
pub struct Metrics {
    pub bind_to_address: String,
}

#[derive(Debug, Deserialize)]
pub struct RateLimits {
    pub public: RateLimit,  // for public endpoints
    pub private: RateLimit, // for authenticated or private endpoints
}

#[derive(Debug, Deserialize)]
pub struct RateLimit {
    pub max_burst: i32,
    pub tokens: i32, // number of requests
    pub period: i32, // requests / period
}

fn get_turnstile_toml_path() -> String {
    env::var("TURNSTILE_TOML").unwrap_or_else(|_| "Turnstile.toml".to_string())
}

lazy_static! {
    pub static ref CONFIG: Config = {
        let turnstile_toml_path = get_turnstile_toml_path();
        let config: Config = toml::from_str(&read_file_to_string(&turnstile_toml_path)).unwrap();
        config
    };
}

fn read_file_to_string(filename: &str) -> String {
    let mut file = File::open(filename).expect("Unable to open the file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Unable to read the file");
    contents
}

pub fn load_config() {
    info!(
        "Loaded Turnstile configuration values from {}",
        get_turnstile_toml_path()
    );
    info!("CONFIG => {:#?}", Paint::red(&*CONFIG));
}
