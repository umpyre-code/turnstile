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
    pub box_public_key: String,
    pub email: String,
    pub full_name: String,
    pub password_hash: String,
    pub phone_number: PhoneNumber,
    pub signing_public_key: String,
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
    pub box_public_key: String,
    pub client_id: String,
    pub full_name: String,
    pub signing_public_key: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateClientRequest {
    pub box_public_key: String,
    pub email: Option<String>,
    pub full_name: String,
    pub password_hash: Option<String>,
    pub phone_number: Option<PhoneNumber>,
    pub signing_public_key: String,
}

#[derive(Debug, Serialize)]
pub struct UpdateClientResponse {
    pub box_public_key: String,
    pub client_id: String,
    pub full_name: String,
    pub signing_public_key: String,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct Message {
    // Fields should be in lexicographical order. Changing the order will break
    // signature & hash verification.
    pub body: String,
    pub from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    pub nonce: String,
    pub pda: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<Timestamp>,
    pub recipient_public_key: String,
    pub sender_public_key: String,
    pub sent_at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub to: String,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: i32,
}

#[derive(Debug, Serialize)]
pub struct GetMessagesResponse {
    pub messages: Vec<Message>,
}
