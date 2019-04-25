use log::info;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use toml;
use yansi::Paint;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub worker_threads: usize,
    pub rolodex: Rolodex,
}

#[derive(Debug, Deserialize)]
pub struct Rolodex {
    pub host: String,
    pub port: i32,
    pub ca_cert_path: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
}

fn get_turnstile_toml_path() -> String {
    env::var("TURNSTILE_TOML").unwrap_or_else(|_| "turnstile.toml".to_string())
}

lazy_static! {
    pub static ref CONFIG: Config = {
        let api_frontend_toml_path = get_turnstile_toml_path();
        let config: Config = toml::from_str(&read_file_to_string(&api_frontend_toml_path)).unwrap();
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
