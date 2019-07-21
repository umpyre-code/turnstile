extern crate assert_cmd;
extern crate data_encoding;
extern crate rand;
extern crate reqwest;
use std::sync::atomic::{AtomicI32, Ordering};
#[macro_use]
extern crate serde_derive;
extern crate sha3;
extern crate sodiumoxide;
extern crate srp;

#[macro_use]
extern crate serde_json;

use data_encoding::BASE64_NOPAD;

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
    use sodiumoxide::crypto::generichash;
    let mut hasher = generichash::State::new(digest_size, None).unwrap();
    hasher.update(s.as_bytes()).unwrap();
    let digest = hasher.finalize().unwrap();
    BASE64_NOPAD.encode(digest.as_ref())
}

struct KeyPairs {
    signing_public_key: String,
    signing_secret_key: String,
    box_public_key: String,
    box_secret_key: String,
}

fn gen_keys() -> KeyPairs {
    use sodiumoxide::crypto::box_;
    use sodiumoxide::crypto::sign;
    let (spk, ssk) = sign::gen_keypair();
    let (bpk, bsk) = box_::gen_keypair();
    KeyPairs {
        signing_public_key: BASE64_NOPAD.encode(spk.as_ref()),
        signing_secret_key: BASE64_NOPAD.encode(ssk.as_ref()),
        box_public_key: BASE64_NOPAD.encode(bpk.as_ref()),
        box_secret_key: BASE64_NOPAD.encode(bsk.as_ref()),
    }
}

fn encrypt_body(keypairs: &KeyPairs, body: &str) -> (String, String) {
    use sodiumoxide::crypto::box_;

    let theirpk = box_::PublicKey::from_slice(
        &BASE64_NOPAD
            .decode(keypairs.box_public_key.as_bytes())
            .unwrap(),
    )
    .unwrap();
    let oursk = box_::SecretKey::from_slice(
        &BASE64_NOPAD
            .decode(keypairs.box_secret_key.as_bytes())
            .unwrap(),
    )
    .unwrap();

    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(body.as_bytes(), &nonce, &theirpk, &oursk);

    (
        BASE64_NOPAD.encode(&ciphertext),
        BASE64_NOPAD.encode(nonce.as_ref()),
    )
}

fn decrypt_body(keypairs: &KeyPairs, body: &str, nonce: &str) -> String {
    use sodiumoxide::crypto::box_;

    let ourpk = box_::PublicKey::from_slice(
        &BASE64_NOPAD
            .decode(keypairs.box_public_key.as_bytes())
            .unwrap(),
    )
    .unwrap();
    let theirsk = box_::SecretKey::from_slice(
        &BASE64_NOPAD
            .decode(keypairs.box_secret_key.as_bytes())
            .unwrap(),
    )
    .unwrap();
    let nonce = box_::Nonce::from_slice(&BASE64_NOPAD.decode(nonce.as_bytes()).unwrap()).unwrap();

    String::from_utf8(
        box_::open(
            &BASE64_NOPAD.decode(body.as_bytes()).unwrap(),
            &nonce,
            &ourpk,
            &theirsk,
        )
        .unwrap(),
    )
    .unwrap()
}

fn create_client<'a>(
    turnstile_process: &Turnstile,
    reqwest: &reqwest::Client,
) -> (AddClient, String, Srp<'a>, KeyPairs) {
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let rand_num: i64 = rng.gen_range(2_000_000, 10_000_000);

    let keypairs = gen_keys();

    let email = format!("test{}@aol.com", rand_num);
    let password = "password";
    let srp = make_srp_client(&email, password);
    let password_verifier = srp.client.get_password_verifier(&srp.private_key);

    let body = json!({
        "full_name": format!("herp derp {}", rand_num),
        "email": email.clone(),
        "password_verifier": BASE64_NOPAD.encode(&password_verifier),
        "password_salt": BASE64_NOPAD.encode(&srp.salt),
        "phone_number": {"country_code":"US","national_number":format!("510{}", rand_num)},
        "box_public_key": keypairs.box_public_key.clone(),
        "signing_public_key": keypairs.signing_public_key.clone(),
    });

    let mut response = reqwest
        .post(&format!("{}/client", turnstile_process.url))
        .json(&body)
        .send()
        .unwrap();

    let add_client: AddClient = response.json().unwrap();
    (add_client, email, srp, keypairs)
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
struct Jwt {
    token: String,
    secret: String,
}

#[derive(Deserialize, Debug)]
struct AddClient {
    client_id: String,
    jwt: Jwt,
}

struct Srp<'a> {
    client: srp::client::SrpClient<'a, sha3::Sha3_512>,
    salt: Vec<u8>,
    private_key: Vec<u8>,
}

fn make_srp_client<'a>(email: &str, password: &str) -> Srp<'a> {
    use rand::RngCore;
    use sha3::Sha3_512;
    use srp::client::srp_private_key;
    use srp::client::SrpClient;
    use srp::groups::G_2048;

    let mut a = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut a);
    let mut salt = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut salt);
    Srp {
        client: SrpClient::<Sha3_512>::new(&a, &G_2048),
        salt: salt.to_vec(),
        private_key: srp_private_key::<Sha3_512>(email.as_bytes(), password.as_bytes(), &salt)
            .to_vec(),
    }
}

#[test]
fn test_add_client() {
    use rand::Rng;
    let turnstile_process = Turnstile::new().wait_for_ping();

    let mut rng = rand::thread_rng();
    let rand_num: i64 = rng.gen_range(2_000_000, 10_000_000);

    let reqwest = reqwest::Client::new();

    let email = format!("lol{}@aol.com", rand_num);
    let password = "password";
    let srp = make_srp_client(&email, password);
    let password_verifier = srp.client.get_password_verifier(&srp.private_key);

    let body = json!({
        "full_name": format!("herp derp {}", rand_num),
        "email": email,
        "password_verifier": BASE64_NOPAD.encode(&password_verifier),
        "password_salt": BASE64_NOPAD.encode(&srp.salt),
        "phone_number": {"country_code":"US","national_number":format!("510{}", rand_num)},
        "box_public_key": "derp key",
        "signing_public_key": "derp key",
    });

    let mut response = reqwest
        .post(&format!("{}/client", turnstile_process.url))
        .json(&body)
        .send()
        .unwrap();

    let add_client: AddClient = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(add_client.client_id.len(), 32);
    assert_eq!(!add_client.jwt.token.is_empty(), true);
}

#[derive(Deserialize, Debug)]
struct AuthHandshake {
    b_pub: String,
}

#[derive(Deserialize, Debug)]
struct AuthVerify {
    client_id: String,
    server_proof: String,
    jwt: Jwt,
}

fn handle_auth(
    email: &str,
    client: &reqwest::Client,
    srp: Srp,
    url: &str,
    add_client: &AddClient,
    temporary: bool,
) -> AuthVerify {
    let temporary = if temporary { "-temporarily" } else { "" };
    // Now we have a valid client, test auth with the existing (current) client
    let body = json!({
        "email": email,
        "a_pub": BASE64_NOPAD.encode(&srp.client.get_a_pub()),
    });
    let mut response = client
        .post(&format!("{}/client/auth{}/handshake", url, temporary))
        .json(&body)
        .send()
        .unwrap();

    let auth_handshake: AuthHandshake = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(auth_handshake.b_pub.is_empty(), false);

    let a_pub = srp.client.get_a_pub().clone();
    let srp_client2 = srp
        .client
        .process_reply(
            &srp.private_key,
            &BASE64_NOPAD
                .decode(auth_handshake.b_pub.as_bytes())
                .unwrap(),
        )
        .unwrap();

    let body = json!({
        "email": email,
        "a_pub": BASE64_NOPAD.encode(&a_pub),
        "client_proof": BASE64_NOPAD.encode(&srp_client2.get_proof()),
    });
    let mut response = client
        .post(&format!("{}/client/auth{}/verify", url, temporary))
        .json(&body)
        .send()
        .unwrap();

    let auth_verify: AuthVerify = response.json().unwrap();
    assert_eq!(auth_verify.client_id, add_client.client_id);
    assert_eq!(auth_verify.server_proof.is_empty(), false);
    assert_eq!(auth_verify.jwt.token.is_empty(), false);
    srp_client2
        .verify_server(
            &BASE64_NOPAD
                .decode(auth_verify.server_proof.as_bytes())
                .unwrap(),
        )
        .unwrap();

    auth_verify
}

#[test]
fn test_authenticate() {
    use rand::Rng;
    let turnstile_process = Turnstile::new().wait_for_ping();

    let mut rng = rand::thread_rng();
    let rand_num: i64 = rng.gen_range(2_000_000, 10_000_000);

    let email = format!("lol{}@aol.com", rand_num);
    let password = "password";
    let srp = make_srp_client(&email, password);
    let password_verifier = srp.client.get_password_verifier(&srp.private_key);

    let client = reqwest::Client::new();

    let body = json!({
        "full_name": format!("herp derp {}", rand_num),
        "email": email.clone(),
        "password_verifier": BASE64_NOPAD.encode(&password_verifier),
        "password_salt": BASE64_NOPAD.encode(&srp.salt),
        "phone_number":{"country_code":"US","national_number":format!("510{}", rand_num)},
        "box_public_key":"derp key",
        "signing_public_key":"derp key",
    });

    let mut response = client
        .post(&format!("{}/client", turnstile_process.url))
        .json(&body)
        .send()
        .unwrap();

    let add_client: AddClient = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(add_client.client_id.len(), 32);
    assert_eq!(!add_client.jwt.token.is_empty(), true);

    // Now we have a valid client, test auth with the existing (current) client
    let _auth_verify = handle_auth(
        &email,
        &client,
        srp,
        &turnstile_process.url,
        &add_client,
        false,
    );
}

#[derive(Deserialize, Debug)]
struct Client {
    client_id: String,
    full_name: String,
    box_public_key: String,
    signing_public_key: String,
    handle: Option<String>,
    profile: Option<String>,
}

#[test]
fn test_get_client() {
    let turnstile_process = Turnstile::new().wait_for_ping();
    let reqwest = reqwest::ClientBuilder::new().build().unwrap();

    let response = reqwest
        .get(&format!("{}/client/{}", turnstile_process.url, "lol"))
        .send()
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    let (this_client, _email, _srp, _keypairs) = create_client(&turnstile_process, &reqwest);

    let mut response = reqwest
        .get(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token)
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name.starts_with("herp derp "), true);
}

#[test]
fn test_update_client() {
    let turnstile_process = Turnstile::new().wait_for_ping();
    let reqwest = reqwest::ClientBuilder::new().build().unwrap();

    let response = reqwest
        .get(&format!("{}/client/{}", turnstile_process.url, "lol"))
        .send()
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    let (this_client, _email, _srp, keypairs) = create_client(&turnstile_process, &reqwest);

    let mut response = reqwest
        .get(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name.starts_with("herp derp "), true);

    // Create a client update message
    let body = json!({
        "client_id": this_client.client_id.clone(),
        "full_name": "arnold",
        "box_public_key": keypairs.box_public_key.clone(),
        "signing_public_key": keypairs.signing_public_key.clone(),
        "handle":this_client.client_id.clone(),
        "profile":"profile"
    });

    let mut response = reqwest
        .put(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .json(&body)
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name, "arnold");
    assert_eq!(client.box_public_key, keypairs.box_public_key);
    assert_eq!(client.signing_public_key, keypairs.signing_public_key);
    assert_eq!(client.handle.unwrap(), this_client.client_id);
    assert_eq!(client.profile.unwrap(), "profile");
}

#[test]
fn test_update_client_password() {
    use reqwest::StatusCode;

    let turnstile_process = Turnstile::new().wait_for_ping();
    let reqwest = reqwest::ClientBuilder::new().build().unwrap();

    let response = reqwest
        .get(&format!("{}/client/{}", turnstile_process.url, "lol"))
        .send()
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    let (this_client, email, srp, _keypairs) = create_client(&turnstile_process, &reqwest);

    let mut response = reqwest
        .get(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name.starts_with("herp derp "), true);

    let new_pw = "AAAA";

    // Create a client update message
    let new_body = json!({
        "client_id": this_client.client_id.clone(),
        "full_name": "arnold",
        "box_public_key": "lyle",
        "signing_public_key": "lyle",
        "password_verifier": new_pw,
        "password_salt": new_pw,
    });

    // Test without a temporary token. Should return 403.
    let response = reqwest
        .put(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .json(&new_body)
        .send()
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Obtain a temporary token
    let auth_verify = handle_auth(
        &email,
        &reqwest,
        srp,
        &turnstile_process.url,
        &this_client,
        true,
    );

    // Test with a temporary token
    let mut response = reqwest
        .put(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .header("X-UMPYRE-TOKEN-TEMP", auth_verify.jwt.token.clone())
        .json(&new_body)
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name, "arnold");
    assert_eq!(client.box_public_key, "lyle");
    assert_eq!(client.signing_public_key, "lyle");
}

#[test]
fn test_update_client_email() {
    use rand::Rng;
    use reqwest::StatusCode;

    let mut rng = rand::thread_rng();
    let rand_num: i64 = rng.gen_range(2_000_000, 10_000_000);

    let turnstile_process = Turnstile::new().wait_for_ping();
    let reqwest = reqwest::ClientBuilder::new().build().unwrap();

    let response = reqwest
        .get(&format!("{}/client/{}", turnstile_process.url, "lol"))
        .send()
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    let (this_client, email, srp, _keypairs) = create_client(&turnstile_process, &reqwest);

    let mut response = reqwest
        .get(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name.starts_with("herp derp "), true);

    // Create a client update message
    let new_body = json!({
        "client_id": this_client.client_id.clone(),
        "full_name": "arnold",
        "box_public_key": "lyle",
        "signing_public_key": "lyle",
        "email": format!("hellllllo{}@aol.com", rand_num),
    });

    // Test without a temporary token. Should return 403.
    let response = reqwest
        .put(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .json(&new_body)
        .send()
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Obtain a temporary token
    let auth_verify = handle_auth(
        &email,
        &reqwest,
        srp,
        &turnstile_process.url,
        &this_client,
        true,
    );

    // Test with a temporary token
    let mut response = reqwest
        .put(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .header("X-UMPYRE-TOKEN-TEMP", auth_verify.jwt.token.clone())
        .json(&new_body)
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name, "arnold");
    assert_eq!(client.box_public_key, "lyle");
    assert_eq!(client.signing_public_key, "lyle");
}

#[test]
fn test_update_client_phone_number() {
    use rand::Rng;
    use reqwest::StatusCode;

    let mut rng = rand::thread_rng();
    let rand_num: i64 = rng.gen_range(2_000_000, 10_000_000);

    let turnstile_process = Turnstile::new().wait_for_ping();
    let reqwest = reqwest::ClientBuilder::new().build().unwrap();

    let response = reqwest
        .get(&format!("{}/client/{}", turnstile_process.url, "lol"))
        .send()
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    let (this_client, email, srp, _keypairs) = create_client(&turnstile_process, &reqwest);

    let mut response = reqwest
        .get(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name.starts_with("herp derp "), true);

    // Create a client update message
    let new_body = json!({
        "client_id": this_client.client_id.clone(),
        "full_name": "arnold",
        "box_public_key": "lyle",
        "signing_public_key": "lyle",
        "phone_number":{"country_code":"US","national_number":format!("510{}", rand_num)},
    });

    // Test without a temporary token. Should return 403.
    let response = reqwest
        .put(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .json(&new_body)
        .send()
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Obtain a temporary token
    let auth_verify = handle_auth(
        &email,
        &reqwest,
        srp,
        &turnstile_process.url,
        &this_client,
        true,
    );

    // Test with a temporary token
    let mut response = reqwest
        .put(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .header("X-UMPYRE-TOKEN-TEMP", auth_verify.jwt.token.clone())
        .json(&new_body)
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name, "arnold");
    assert_eq!(client.box_public_key, "lyle");
    assert_eq!(client.signing_public_key, "lyle");
}

#[derive(Debug, Deserialize)]
pub struct ReceiveMessage {
    pub to: String,
    pub from: String,
    pub body: String,
    pub hash: String,
    pub received_at: Timestamp,
    pub nonce: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Timestamp {
    pub nanos: i32,
    pub seconds: i64,
}

#[derive(Debug, Deserialize)]
pub struct Messages {
    pub messages: Vec<ReceiveMessage>,
}

#[derive(Debug, Serialize)]
pub struct SendMessage {
    pub body: String,
    pub from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    pub nonce: String,
    pub pda: String,
    pub recipient_public_key: String,
    pub sender_public_key: String,
    pub sent_at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub to: String,
}

#[test]
fn test_send_message() {
    use sodiumoxide::crypto::sign;

    let turnstile_process = Turnstile::new().wait_for_ping();
    let reqwest = reqwest::ClientBuilder::new().build().unwrap();

    let response = reqwest
        .get(&format!("{}/client/{}", turnstile_process.url, "lol"))
        .send()
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    let (this_client, _email, _srp, keypairs) = create_client(&turnstile_process, &reqwest);

    let mut response = reqwest
        .get(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name.starts_with("herp derp "), true);

    let original_body = "derp";
    let (body, nonce) = encrypt_body(&keypairs, &original_body);

    // Create a message, send to self
    let message = SendMessage {
        body,
        nonce,
        from: this_client.client_id.clone(),
        hash: None,
        pda: "hello".into(),
        recipient_public_key: keypairs.box_public_key.clone(),
        sender_public_key: keypairs.box_public_key.clone(),
        sent_at: Timestamp {
            nanos: 1,
            seconds: 1,
        },
        signature: None,
        to: this_client.client_id.clone(),
    };

    // Compute hash
    let message_json = serde_json::to_string(&message).unwrap();
    let hash = b2b_hash(&message_json, 32);
    let message = SendMessage {
        hash: Some(hash),
        ..message
    };

    // Compute signature
    let message_json = serde_json::to_string(&message).unwrap();
    let signing_secret_key = sign::SecretKey::from_slice(
        &BASE64_NOPAD
            .decode(keypairs.signing_secret_key.as_bytes())
            .unwrap(),
    )
    .unwrap();

    let signature = BASE64_NOPAD
        .encode(&sign::sign_detached(message_json.as_bytes(), &signing_secret_key).as_ref());
    let message = SendMessage {
        signature: Some(signature),
        ..message
    };

    // Send the message
    let mut response = reqwest
        .post(&format!("{}/messages", turnstile_process.url))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .json(&message)
        .send()
        .unwrap();

    assert_eq!(response.status().is_success(), true);

    let message: ReceiveMessage = response.json().unwrap();

    assert_eq!(message.hash.is_empty(), false);
    assert_eq!(message.from, this_client.client_id);

    // Check that the message is now in inbox
    let mut response = reqwest
        .get(&format!("{}/messages", turnstile_process.url))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .send()
        .unwrap();

    let messages: Messages = response.json().unwrap();
    let messages = messages.messages;
    assert_eq!(messages.len(), 1);

    // decrypt message body
    let decrypted_body = decrypt_body(&keypairs, &messages[0].body, &messages[0].nonce);
    assert_eq!(original_body, decrypted_body);
}

#[test]
fn test_get_client_anonymously() {
    let turnstile_process = Turnstile::new().wait_for_ping();
    let reqwest = reqwest::ClientBuilder::new().build().unwrap();

    let response = reqwest
        .get(&format!("{}/client/{}", turnstile_process.url, "lol"))
        .send()
        .unwrap();

    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    let (this_client, _email, _srp, keypairs) = create_client(&turnstile_process, &reqwest);

    let mut response = reqwest
        .get(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name.starts_with("herp derp "), true);

    // Create a client update message
    let body = json!({
        "client_id": this_client.client_id.clone(),
        "full_name": "arnold",
        "box_public_key": keypairs.box_public_key.clone(),
        "signing_public_key": keypairs.signing_public_key.clone(),
        "handle":this_client.client_id.clone(),
        "profile":"profile"
    });

    let mut response = reqwest
        .put(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .header("X-UMPYRE-TOKEN", this_client.jwt.token.clone())
        .json(&body)
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name, "arnold");
    assert_eq!(client.box_public_key, keypairs.box_public_key);
    assert_eq!(client.signing_public_key, keypairs.signing_public_key);
    assert_eq!(client.handle.unwrap(), this_client.client_id);
    assert_eq!(client.profile.unwrap(), "profile");

    // Get client by client_id
    let mut response = reqwest
        .get(&format!(
            "{}/client/{}",
            turnstile_process.url, this_client.client_id
        ))
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name, "arnold");
    assert_eq!(client.box_public_key, keypairs.box_public_key);
    assert_eq!(client.signing_public_key, keypairs.signing_public_key);
    assert_eq!(client.handle.unwrap(), this_client.client_id);
    assert_eq!(client.profile.unwrap(), "profile");

    // Get client by handle
    let mut response = reqwest
        .get(&format!(
            "{}/handle/{}",
            turnstile_process.url, this_client.client_id
        ))
        .send()
        .unwrap();

    let client: Client = response.json().unwrap();

    assert_eq!(response.status().is_success(), true);
    assert_eq!(client.client_id, this_client.client_id);
    assert_eq!(client.full_name, "arnold");
    assert_eq!(client.box_public_key, keypairs.box_public_key);
    assert_eq!(client.signing_public_key, keypairs.signing_public_key);
    assert_eq!(client.handle.unwrap(), this_client.client_id);
    assert_eq!(client.profile.unwrap(), "profile");
}
