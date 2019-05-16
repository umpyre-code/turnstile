extern crate assert_cmd;
extern crate data_encoding;
extern crate rand;
extern crate reqwest;
use std::sync::atomic::{AtomicI32, Ordering};
#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate serde_json;

struct Turnstile {
    child: std::process::Child,
    pub url: String,
}

impl Drop for Turnstile {
    fn drop(&mut self) {
        self.stop();
    }
}

static GLOBAL_PORT_COUNTER: AtomicI32 = AtomicI32::new(10_000);

impl Turnstile {
    fn new() -> Self {
        use assert_cmd::prelude::*;
        use std::process::Command;

        // Get next available
        let port = GLOBAL_PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let url = format!("http://localhost:{}", port);

        // Fork binary to background
        Turnstile {
            child: Command::cargo_bin("turnstile")
                .unwrap()
                .env("DISABLE_INSTRUMENTED", "1")
                .env("ROCKET_PORT", format!("{}", port))
                .spawn()
                .expect("Failed to start turnstile process"),
            url,
        }
    }

    fn wait_for_ping(self) -> Self {
        use std::{thread, time};

        let reqwest = reqwest::Client::new();
        while reqwest.get(&format!("{}/ping", self.url)).send().is_err() {
            thread::sleep(time::Duration::from_millis(10));
        }

        self
    }

    fn stop(&mut self) {
        use nix::libc::pid_t;
        use nix::sys::signal::*;
        use nix::unistd::*;

        // Send SIGINT
        kill(Pid::from_raw(self.child.id() as pid_t), SIGINT).expect("kill failed");
        // Wait for process to finish
        self.child.wait().expect("Failed to stop turnstile");
    }
}

fn b2b_hash(s: &str, digest_size: usize) -> String {
    use data_encoding::BASE64_NOPAD;
    use sodiumoxide::crypto::generichash;
    let mut hasher = generichash::State::new(digest_size, None).unwrap();
    hasher.update(s.as_bytes()).unwrap();
    let digest = hasher.finalize().unwrap();
    BASE64_NOPAD.encode(digest.as_ref())
}

fn create_client(turnstile_process: &Turnstile, reqwest: &reqwest::Client) -> AddClient {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let rand_num: i64 = rng.gen_range(2_000_000, 10_000_000);

    let body = json!({
        "full_name": format!("herp derp {}", rand_num),
        "email": format!("test{}@aol.com", rand_num),
        "password_hash":
     b2b_hash("derp", 64    ),
        "phone_number":{"country_code":"US","national_number":format!("510{}", rand_num)},
        "public_key":"derp key"
    });

    let mut response = reqwest
        .post(&format!("{}/client", turnstile_process.url))
        .json(&body)
        .send()
        .unwrap();

    let add_client: AddClient = response.json().unwrap();
    add_client
}

#[test]
fn test_ping() {
    let turnstile_process = Turnstile::new().wait_for_ping();

    let client = reqwest::Client::new();
    let mut res = client
        .get(&format!("{}/ping", turnstile_process.url))
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "pong")
}

#[derive(Deserialize, Debug)]
struct AddClient {
    client_id: String,
    token: String,
}

#[test]
fn test_add_client() {
    use rand::Rng;
    let turnstile_process = Turnstile::new().wait_for_ping();

    let mut rng = rand::thread_rng();
    let rand_num: i64 = rng.gen_range(2_000_000, 10_000_000);

    let reqwest = reqwest::Client::new();
    let password_hash = b2b_hash("derp", 64);
    let body = json!({
        "full_name": format!("herp derp {}", rand_num),
        "email": format!("lol{}@aol.com", rand_num),
        "password_hash":password_hash,
        "phone_number":{"country_code":"US","national_number":format!("510{}", rand_num)},
        "public_key":"derp key"
    });

    let mut response = reqwest
        .post(&format!("{}/client", turnstile_process.url))
        .json(&body)
        .send()
        .unwrap();

    let add_client: AddClient = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(add_client.client_id.len(), 32);
    assert_eq!(!add_client.token.is_empty(), true);

    let token = response
        .cookies()
        .find(|cookie| cookie.name() == "X-UMPYRE-APIKEY")
        .unwrap();
    assert_eq!(add_client.token, token.value());
}

#[derive(Deserialize, Debug)]
struct Authenticate {
    client_id: String,
    token: String,
}

#[test]
fn test_authenticate() {
    use rand::Rng;
    let turnstile_process = Turnstile::new().wait_for_ping();

    let mut rng = rand::thread_rng();
    let rand_num: i64 = rng.gen_range(2_000_000, 10_000_000);

    let client = reqwest::Client::new();
    let password_hash = b2b_hash("derp", 64);
    let body = json!({
        "full_name": format!("herp derp {}", rand_num),
        "email": format!("lol{}@aol.com", rand_num),
        "password_hash":password_hash.clone(),
        "phone_number":{"country_code":"US","national_number":format!("510{}", rand_num)},
        "public_key":"derp key"
    });

    let mut response = client
        .post(&format!("{}/client", turnstile_process.url))
        .json(&body)
        .send()
        .unwrap();

    let add_client: AddClient = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(add_client.client_id.len(), 32);
    assert_eq!(!add_client.token.is_empty(), true);

    let token = response
        .cookies()
        .find(|cookie| cookie.name() == "X-UMPYRE-APIKEY")
        .unwrap();
    assert_eq!(add_client.token, token.value());

    // Now we have a valid client, test auth with the existing (current) client
    let body = json!({
        "client_id": add_client.client_id,
        "password_hash":password_hash,
    });
    let mut response = client
        .post(&format!("{}/client/authenticate", turnstile_process.url))
        .json(&body)
        .send()
        .unwrap();

    let authenticate: Authenticate = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(authenticate.client_id, add_client.client_id);
    assert_eq!(!authenticate.token.is_empty(), true);
    assert_ne!(authenticate.token, add_client.token);
}

#[derive(Deserialize, Debug)]
struct Client {
    client_id: String,
    full_name: String,
}

#[test]
fn test_get_client() {
    let turnstile_process = Turnstile::new().wait_for_ping();
    let reqwest = reqwest::ClientBuilder::new()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = reqwest
        .get(&format!("{}/client/{}", turnstile_process.url, "lol"))
        .send()
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    let this_client = create_client(&turnstile_process, &reqwest);

    let mut response = reqwest
        .get(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-APIKEY", this_client.token)
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name.starts_with("herp derp "), true);
}
