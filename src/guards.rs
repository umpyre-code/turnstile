use crate::fairings::RedisReader;
use crate::token;

#[derive(Debug, Clone)]
pub struct User {
    pub user_id: String,
}

impl<'a, 'r> rocket::request::FromRequest<'a, 'r> for User {
    type Error = ();

    fn from_request(
        request: &'a rocket::request::Request<'r>,
    ) -> rocket::request::Outcome<User, Self::Error> {
        use rocket::http::Status;
        use rocket::outcome::IntoOutcome;
        use rocket_contrib::databases::redis::Commands;

        let redis_reader = request.guard::<RedisReader>().unwrap();
        let redis = &*redis_reader;
        request
            .cookies()
            .get("X-UMPYRE-APIKEY")
            .and_then(|cookie| Some(cookie.value()))
            .or_else(|| request.headers().get_one("X-UMPYRE-APIKEY"))
            .map(std::string::ToString::to_string)
            .and_then(|token: String| match token::decode_into_sub(&token) {
                Ok(user_id) => Some((token, user_id)),
                Err(_) => None,
            })
            .and_then(|(token, user_id)| {
                let is_member: bool = redis
                    .sismember(&format!("token:{}", user_id), token)
                    .unwrap();
                if is_member {
                    Some(User { user_id })
                } else {
                    None
                }
            })
            .into_outcome((Status::Unauthorized, ()))
    }
}
