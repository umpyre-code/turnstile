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
    pub country_code: String, // two letter country code
    pub national_number: String,
}

#[derive(Debug, Deserialize)]
pub struct NewUserRequest {
    pub full_name: String,
    pub password_hash: String,
    pub email: String,
    pub phone_number: PhoneNumber,
    pub public_key: String,
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
    pub public_key: String,
}
