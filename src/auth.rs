use crate::error::ResponseError;
use crate::models;
use crate::redis::db;
use crate::token;

fn generate_and_store_token(
    redis_writer: &mut db::WriterConnection,
    client_id: &str,
    expiry: u64,
) -> Result<models::Jwt, ResponseError> {
    use r2d2_redis_cluster::Commands;

    // generate token (JWT)
    let jwt = token::generate(&client_id, expiry);

    // store token in Redis
    let redis = &mut *redis_writer;
    redis.0.set_ex(
        &format!("token:{}:{}", client_id, jwt.jti),
        &jwt.secret,
        expiry as usize,
    )?;

    Ok(models::Jwt {
        token: jwt.token,
        secret: jwt.secret,
    })
}

pub fn generate_auth_token(
    redis_writer: &mut db::WriterConnection,
    client_id: &str,
) -> Result<models::Jwt, ResponseError> {
    // 1 year expiry
    let expiry = 365 * 24 * 3600;

    generate_and_store_token(redis_writer, client_id, expiry)
}

pub fn generate_auth_temporary_token(
    redis_writer: &mut db::WriterConnection,
    client_id: &str,
) -> Result<models::Jwt, ResponseError> {
    // 1 hour expiry
    let expiry = 3600;

    generate_and_store_token(redis_writer, client_id, expiry)
}

pub fn verify_auth_token_get_sub(
    redis_reader: &mut db::ReaderConnection,
    token: &str,
) -> Result<String, ResponseError> {
    use r2d2_redis_cluster::Commands;

    let jwt = token::decode_sub(token)?;

    let secret: String = redis_reader
        .0
        .get(&format!("token:{}:{}", jwt.sub, jwt.jti))?;

    let jwt = token::decode_and_verify(token, &secret)?;

    Ok(jwt.sub)
}

#[cfg(test)]
mod test {
    use super::*;

    fn get_redis_conn() -> rocket_contrib::databases::redis::Connection {
        let client = rocket_contrib::databases::redis::Client::open("redis://127.0.0.1/").unwrap();
        client.get_connection().unwrap()
    }

    #[test]
    fn test_auth_token() {
        let redis_conn = get_redis_conn();
        let jwt = generate_auth_token(&redis_conn, "bob").unwrap();
        let sub = verify_auth_token_get_sub(&redis_conn, &jwt.token).unwrap();
        assert_eq!(&sub, "bob");
    }
}
