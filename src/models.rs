#[derive(Debug, Deserialize)]
pub struct AuthHandshakeRequest {
    pub a_pub: String,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct AuthHandshakeResponse {
    pub b_pub: String,
    pub salt: String,
}

#[derive(Debug, Deserialize)]
pub struct AuthVerifyRequest {
    pub a_pub: String,
    pub client_proof: String,
    pub email: String,
}

#[derive(Debug, Serialize)]
pub struct Jwt {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct AuthVerifyResponse {
    pub client_id: String,
    pub server_proof: String,
    pub jwt: Jwt,
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
    pub password_verifier: String,
    pub password_salt: String,
    pub phone_number: PhoneNumber,
    pub signing_public_key: String,
    #[serde(default)]
    pub referred_by: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct NewClientResponse {
    pub client_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct GetClientResponse {
    pub box_public_key: String,
    pub client_id: String,
    pub full_name: String,
    pub signing_public_key: String,
    pub handle: Option<String>,
    pub profile: Option<String>,
    pub joined: i64,
    pub phone_sms_verified: bool,
    pub ral: i32,
    pub avatar_version: i32,
}

#[derive(Debug, Deserialize)]
pub struct UpdateClientRequest {
    pub box_public_key: String,
    pub email: Option<String>,
    pub full_name: String,
    pub password_verifier: Option<String>,
    pub password_salt: Option<String>,
    pub phone_number: Option<PhoneNumber>,
    pub signing_public_key: String,
    pub handle: Option<String>,
    pub profile: Option<String>,
    pub joined: i64,
    pub phone_sms_verified: bool,
    pub ral: i32,
    pub avatar_version: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpdateClientResponse {
    pub box_public_key: String,
    pub client_id: String,
    pub full_name: String,
    pub signing_public_key: String,
    pub handle: Option<String>,
    pub profile: Option<String>,
    pub joined: i64,
    pub phone_sms_verified: bool,
    pub ral: i32,
    pub avatar_version: i32,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<Timestamp>,
    pub recipient_public_key: String,
    pub sender_public_key: String,
    pub sent_at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub to: String,
    pub value_cents: i32,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
pub struct Timestamp {
    pub nanos: i32,
    pub seconds: i64,
}

#[derive(Default, Debug, Serialize)]
pub struct Balance {
    pub client_id: String,
    pub balance_cents: i64,
    pub promo_cents: i64,
    pub withdrawable_cents: i64,
}

#[derive(Debug, Serialize)]
pub struct GetAccountBalanceResponse {
    pub balance: Balance,
}

#[derive(Debug, Deserialize)]
pub struct StripeChargeRequest {
    pub amount_cents: i32,
    pub token: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct StripeChargeResponse {
    pub result: String,
    pub api_response: serde_json::Value,
    pub message: String,
    pub balance: Option<Balance>,
}

#[derive(Debug, Serialize)]
pub struct GetConnectAccountResponse {
    pub client_id: String,
    pub connect_account: ConnectAccountInfo,
}

#[derive(Debug, Deserialize)]
pub struct CompleteConnectOauthRequest {
    pub authorization_code: String,
    pub oauth_state: String,
}

#[derive(Debug, Serialize)]
pub struct CompleteConnectOauthResponse {
    pub client_id: String,
    pub connect_account: ConnectAccountInfo,
}

#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ConnectAccountPrefs {
    pub enable_automatic_payouts: bool,
    pub automatic_payout_threshold_cents: i64,
}

#[derive(Debug, Serialize)]
pub struct ConnectAccountInfo {
    pub state: String,
    pub login_link_url: Option<String>,
    pub oauth_url: Option<String>,
    pub preferences: ConnectAccountPrefs,
}

#[derive(Debug, Deserialize)]
pub struct ConnectPayoutRequest {
    pub amount_cents: i32,
}

#[derive(Debug, Serialize)]
pub struct ConnectPayoutResponse {
    pub result: String,
    pub balance: Balance,
}

#[derive(Debug, Serialize)]
pub struct SettlePaymentResponse {
    // The fee collected by Umpyre
    pub fee_cents: i32,
    // The payout amount
    pub payment_cents: i32,
    pub balance: Balance,
}

#[derive(Debug, Serialize)]
pub struct VerifyPhoneResponse {
    pub result: String,
    pub client: Option<GetClientResponse>,
}

#[derive(Debug, Serialize)]
pub struct SendVerificationCodeResponse {}

#[derive(Debug, Serialize)]
pub struct ImageUploadResponse {}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientPrefs {
    pub email_notifications: String,
}

#[derive(Debug, Serialize)]
pub struct SendMessage {
    pub body: String,
    pub from: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    pub nonce: String,
    pub recipient_public_key: String,
    pub sender_public_key: String,
    pub sent_at: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    pub to: String,
    pub value_cents: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Transaction {
    pub created_at: Timestamp,
    pub tx_type: String,
    pub tx_reason: String,
    pub amount_cents: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct AmountByDate {
    pub amount_cents: i64,
    pub year: i32,
    pub month: i32,
    pub day: i32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct Stats {
    pub message_read_amount: Vec<AmountByDate>,
    pub message_sent_amount: Vec<AmountByDate>,
}
