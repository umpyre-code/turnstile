#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub user_id: String,
    pub password_hash: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthResponse {
    pub user_id: String,
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct PhoneNumber {
    pub country: String, // two letter country code
    pub number: String,  // national number
}

#[derive(Debug, Deserialize)]
pub struct NewUserRequest {
    pub full_name: String,
    pub password_hash: String,
    pub email: String,
    pub phone_number: PhoneNumber,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct NewUserResponse {
    pub user_id: String,
    pub token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GetUserResponse {
    pub user_id: String,
    pub full_name: String,
}
