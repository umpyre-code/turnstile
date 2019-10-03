use crate::config;
use crate::error::ResponseError;
use crate::models;
use crate::redis::db;
use crate::token;

fn generate_and_store_token(
    redis_writer: &mut db::WriterConnection,
    client_id: &str,
    expiry: u64,
    secret: &[u8],
) -> Result<models::Jwt, ResponseError> {
    use crate::redis::db::redis;
    use r2d2_redis_cluster::redis_cluster_rs::Commands;

    // generate token (JWT)
    let jwt = token::generate(&client_id, expiry, secret);

    // store token in Redis
    let redis = &mut *redis_writer;
    redis.0.set_ex(
        &format!("token:{}:{}", client_id, jwt.jti),
        secret,
        expiry as usize,
    )?;
    let _res: (i32) = redis::cmd("WAIT")
        .arg(config::CONFIG.redis.replicas_per_master)
        .arg(0)
        .query(&mut redis.0)?;

    Ok(models::Jwt { token: jwt.token })
}

pub fn generate_auth_token(
    redis_writer: &mut db::WriterConnection,
    client_id: &str,
    secret: &[u8],
) -> Result<models::Jwt, ResponseError> {
    // 5 year expiry
    let expiry = 5 * 365 * 24 * 3600;

    generate_and_store_token(redis_writer, client_id, expiry, secret)
}

pub fn generate_auth_temporary_token(
    redis_writer: &mut db::WriterConnection,
    client_id: &str,

    secret: &[u8],
) -> Result<models::Jwt, ResponseError> {
    // 1 hour expiry
    let expiry = 3600;

    generate_and_store_token(redis_writer, client_id, expiry, secret)
}

pub fn verify_auth_token_get_sub(
    redis_reader: &mut db::ReaderConnection,
    token: &str,
) -> Result<String, ResponseError> {
    use r2d2_redis_cluster::Commands;

    let jwt = token::decode_sub(token)?;

    let secret: Vec<u8> = redis_reader
        .0
        .get(&format!("token:{}:{}", jwt.sub, jwt.jti))?;

    let jwt = token::decode_and_verify(token, &secret)?;

    Ok(jwt.sub)
}

pub fn delete_tokens_for(
    redis_writer: &mut db::WriterConnection,
    client_id: &str,
) -> Result<(), ResponseError> {
    use r2d2_redis_cluster::redis_cluster_rs::{pipe, Commands, PipelineCommands};

    let redis = &mut *redis_writer;
    // Fetch all keys for this client
    let keys: (Vec<String>) = redis.0.keys(format!("token:{}:*", client_id))?;

    let mut pipe = pipe();

    for key in keys.iter() {
        pipe.del(key);
    }
    pipe.query(&mut redis.0)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::redis::db::{ReaderConnectionManager, WriterConnectionManager};

    fn get_writer_redis_pool() -> r2d2_redis_cluster::r2d2::Pool<WriterConnectionManager> {
        use r2d2_redis_cluster::r2d2::Pool;
        let manager = WriterConnectionManager::new("127.0.0.1:6379").unwrap();
        let pool = Pool::builder().build(manager).unwrap();

        pool
    }

    fn get_reader_redis_pool() -> r2d2_redis_cluster::r2d2::Pool<ReaderConnectionManager> {
        use r2d2_redis_cluster::r2d2::Pool;
        let manager = ReaderConnectionManager::new("127.0.0.1:6379").unwrap();
        let pool = Pool::builder().build(manager).unwrap();

        pool
    }

    #[test]
    fn test_auth_token() {
        let writer_pool = get_writer_redis_pool();
        let reader_pool = get_reader_redis_pool();
        let mut writer = writer_pool.get().unwrap();
        let mut reader = reader_pool.get().unwrap();
        let jwt = generate_auth_token(&mut writer, "bob", b"secret").unwrap();
        let sub = verify_auth_token_get_sub(&mut reader, &jwt.token).unwrap();
        assert_eq!(&sub, "bob");
    }

    #[test]
    fn test_delete_tokens() {
        let writer_pool = get_writer_redis_pool();
        let reader_pool = get_reader_redis_pool();
        let mut writer = writer_pool.get().unwrap();
        let mut reader = reader_pool.get().unwrap();
        let jwt = generate_auth_token(&mut writer, "bob", b"secret").unwrap();
        let sub = verify_auth_token_get_sub(&mut reader, &jwt.token).unwrap();
        assert_eq!(&sub, "bob");
        delete_tokens_for(&mut writer, "bob").expect("couldn't delete tokens");
    }
}
