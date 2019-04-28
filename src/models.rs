use validator::Validate;

#[derive(Debug, Validate, Deserialize)]
pub struct AuthRequest {
    #[validate(length(equal = "32"))]
    pub user_id: String,
    #[validate(length(equal = "64"))]
    pub password_hash: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AuthResponse {
    pub user_id: String,
    pub token: String,
}
