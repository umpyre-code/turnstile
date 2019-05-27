#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub client_id: String,
    pub password_hash: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthResponse {
    pub client_id: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct PhoneNumber {
    pub country_code: String, // two letter country code
    pub national_number: String,
}

#[derive(Debug, Deserialize)]
pub struct NewClientRequest {
    pub full_name: String,
    pub password_hash: String,
    pub email: String,
    pub phone_number: PhoneNumber,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct NewClientResponse {
    pub client_id: String,
    pub token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GetClientResponse {
    pub client_id: String,
    pub full_name: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateClientRequest {
    pub full_name: String,
    pub public_key: String,
    pub password_hash: Option<String>,
    pub email: Option<String>,
    pub phone_number: Option<PhoneNumber>,
}

#[derive(Debug, Serialize)]
pub struct UpdateClientResponse {
    pub client_id: String,
    pub full_name: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Message {
    pub to: String,
    #[serde(default)]
    pub from: String,
    pub body: String,
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub received_at: Timestamp,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: i32,
}

#[derive(Debug, Serialize)]
pub struct GetMessagesResponse {
    pub messages: Vec<Message>,
}
