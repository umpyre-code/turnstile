extern crate assert_cmd;
extern crate data_encoding;
extern crate reqwest;
extern crate sha2;

#[macro_use]
extern crate serde_json;

struct Turnstile(std::process::Child);

impl Drop for Turnstile {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Turnstile {
    fn new() -> Self {
        use assert_cmd::prelude::*;
        use std::process::Command;

        // Fork binary to background
        Turnstile(
            Command::cargo_bin("turnstile")
                .unwrap()
                .spawn()
                .expect("Failed to start turnstile process"),
        )
    }

    fn wait_for_ping(self) -> Self {
        use std::{thread, time};

        let client = reqwest::Client::new();
        while client.get("http://localhost:8000/ping").send().is_err() {
            thread::sleep(time::Duration::from_millis(10));
        }

        self
    }

    fn stop(&mut self) {
        use nix::libc::pid_t;
        use nix::sys::signal::*;
        use nix::unistd::*;

        // Send SIGINT
        kill(Pid::from_raw(self.0.id() as pid_t), SIGINT).expect("kill failed");
        // Wait for process to finish
        self.0.wait().expect("Failed to stop turnstile");
    }
}

#[test]
fn test_ping() {
    let _turnstile_process = Turnstile::new().wait_for_ping();

    let client = reqwest::Client::new();
    let mut res = client.get("http://localhost:8000/ping").send().unwrap();
    assert_eq!(res.text().unwrap(), "pong")
}

#[test]
fn test_add_user() {
    use data_encoding::HEXLOWER;
    use sha2::{Digest, Sha256};
    let _turnstile_process = Turnstile::new().wait_for_ping();

    let client = reqwest::Client::new();
    let password_hash = HEXLOWER.encode(&Sha256::digest(b"derp"));
    let body = json!({
        "full_name": "herp derp",
        "email":"lol@aol.com",
        "password_hash":password_hash,
        "phone_number":{"country":"US","number":"4024922919"},
    });

    let mut res = client
        .post("http://localhost:8000/user")
        .json(&body)
        .send()
        .unwrap();
    assert_eq!(res.text().unwrap(), "pong")
}
