extern crate assert_cmd;
extern crate data_encoding;
extern crate rand;
extern crate reqwest;
extern crate sha2;
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

        let client = reqwest::Client::new();
        while client.get(&format!("{}/ping", self.url)).send().is_err() {
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

fn create_user(turnstile_process: &Turnstile, client: &reqwest::Client) -> AddUser {
    use data_encoding::HEXLOWER;
    use rand::Rng;
    use sha2::{Digest, Sha256};

    let mut rng = rand::thread_rng();
    let rand_num: i64 = rng.gen_range(2_000_000, 10_000_000);

    let body = json!({
        "full_name": format!("herp derp {}", rand_num),
        "email": format!("test{}@aol.com", rand_num),
        "password_hash":
     HEXLOWER.encode(&Sha256::digest(b"derp")),
        "phone_number":{"country":"US","number":format!("510{}", rand_num)},
        "public_key":"derp key"
    });

    let mut response = client
        .post(&format!("{}/user", turnstile_process.url))
        .json(&body)
        .send()
        .unwrap();

    let add_user: AddUser = response.json().unwrap();
    add_user
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
struct AddUser {
    user_id: String,
    token: String,
}

#[test]
fn test_add_user() {
    use data_encoding::HEXLOWER;

    use rand::Rng;
    use sha2::{Digest, Sha256};
    let turnstile_process = Turnstile::new().wait_for_ping();

    let mut rng = rand::thread_rng();
    let rand_num: i64 = rng.gen_range(2_000_000, 10_000_000);

    let client = reqwest::Client::new();
    let password_hash = HEXLOWER.encode(&Sha256::digest(b"derp"));
    let body = json!({
        "full_name": format!("herp derp {}", rand_num),
        "email": format!("lol{}@aol.com", rand_num),
        "password_hash":password_hash,
        "phone_number":{"country":"US","number":format!("510{}", rand_num)},
        "public_key":"derp key"
    });

    let mut response = client
        .post(&format!("{}/user", turnstile_process.url))
        .json(&body)
        .send()
        .unwrap();

    let add_user: AddUser = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(add_user.user_id.len(), 32);
    assert_eq!(!add_user.token.is_empty(), true);

    let token = response
        .cookies()
        .find(|cookie| cookie.name() == "X-UMPYRE-APIKEY")
        .unwrap();
    assert_eq!(add_user.token, token.value());
}

#[derive(Deserialize, Debug)]
struct Authenticate {
    user_id: String,
    token: String,
}

#[test]
fn test_authenticate() {
    use data_encoding::HEXLOWER;

    use rand::Rng;
    use sha2::{Digest, Sha256};
    let turnstile_process = Turnstile::new().wait_for_ping();

    let mut rng = rand::thread_rng();
    let rand_num: i64 = rng.gen_range(2_000_000, 10_000_000);

    let client = reqwest::Client::new();
    let password_hash = HEXLOWER.encode(&Sha256::digest(b"derp"));
    let body = json!({
        "full_name": format!("herp derp {}", rand_num),
        "email": format!("lol{}@aol.com", rand_num),
        "password_hash":password_hash.clone(),
        "phone_number":{"country":"US","number":format!("510{}", rand_num)},
        "public_key":"derp key"
    });

    let mut response = client
        .post(&format!("{}/user", turnstile_process.url))
        .json(&body)
        .send()
        .unwrap();

    let add_user: AddUser = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(add_user.user_id.len(), 32);
    assert_eq!(!add_user.token.is_empty(), true);

    let token = response
        .cookies()
        .find(|cookie| cookie.name() == "X-UMPYRE-APIKEY")
        .unwrap();
    assert_eq!(add_user.token, token.value());

    // Now we have a valid user, test auth with the existing (current) client
    let body = json!({
        "user_id": add_user.user_id,
        "password_hash":password_hash,
    });
    let mut response = client
        .post(&format!("{}/user/authenticate", turnstile_process.url))
        .json(&body)
        .send()
        .unwrap();

    let authenticate: Authenticate = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(authenticate.user_id, add_user.user_id);
    assert_eq!(!authenticate.token.is_empty(), true);
    assert_ne!(authenticate.token, add_user.token);
}

#[derive(Deserialize, Debug)]
struct User {
    user_id: String,
    full_name: String,
}

#[test]
fn test_get_user() {
    let turnstile_process = Turnstile::new().wait_for_ping();
    let client = reqwest::ClientBuilder::new()
        .cookie_store(true)
        .build()
        .unwrap();

    let response = client
        .get(&format!("{}/user/{}", turnstile_process.url, "lol"))
        .send()
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);

    let this_user = create_user(&turnstile_process, &client);

    let mut response = client
        .get(&format!(
            "{}/user/{}",
            turnstile_process.url, this_user.user_id
        ))
        .header("X-UMPYRE-APIKEY", this_user.token)
        .send()
        .unwrap();

    let user: User = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(user.user_id, this_user.user_id);
    assert_eq!(user.full_name.starts_with("herp derp "), true);
}
