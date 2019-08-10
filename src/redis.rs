use r2d2_redis_cluster::r2d2::Pool;
use rocket_contrib::databases::{r2d2, DatabaseConfig, DbError, Poolable};

pub mod db {
    pub use r2d2_redis_cluster::redis_cluster_rs::redis;
    pub use r2d2_redis_cluster::redis_cluster_rs::redis::RedisError;
    use r2d2_redis_cluster::redis_cluster_rs::Connection as ClusterConnection;
    use r2d2_redis_cluster::RedisClusterConnectionManager;

    pub struct ReaderConnection(pub ClusterConnection);
    pub struct WriterConnection(pub ClusterConnection);
    pub struct WriterConnectionManager(RedisClusterConnectionManager);
    pub struct ReaderConnectionManager(RedisClusterConnectionManager);

    type Result<T> = ::std::result::Result<T, RedisError>;

    impl WriterConnectionManager {
        pub fn new(url: &str) -> Result<Self> {
            use r2d2_redis_cluster::redis_cluster_rs::redis::IntoConnectionInfo;
            info!("Starting redis writer manager for {}", url);
            let mut manager = RedisClusterConnectionManager::new(
                vec![url.to_owned()]
                    .iter()
                    .map(|c| c.into_connection_info().unwrap())
                    .collect(),
            )?;
            manager.set_readonly(false);
            Ok(Self(manager))
        }
    }

    impl ReaderConnectionManager {
        pub fn new(url: &str) -> Result<Self> {
            info!("Starting redis reader manager for {}", url);
            let mut manager = RedisClusterConnectionManager::new(
                vec![url.to_owned()]
                    .iter()
                    .map(|c| c.into_connection_info().unwrap())
                    .collect(),
            )?;
            manager.set_readonly(true);
            Ok(Self(manager))
        }
    }

    impl r2d2_redis_cluster::r2d2::ManageConnection for WriterConnectionManager {
        type Connection = WriterConnection;
        type Error = RedisError;
        fn connect(&self) -> Result<Self::Connection> {
            match self.0.connect() {
                Ok(connection) => Ok(WriterConnection(connection)),
                Err(err) => Err(err),
            }
        }
        fn is_valid(&self, conn: &mut Self::Connection) -> Result<()> {
            self.0.is_valid(&mut conn.0)
        }
        fn has_broken(&self, conn: &mut Self::Connection) -> bool {
            self.0.has_broken(&mut conn.0)
        }
    }

    impl r2d2_redis_cluster::r2d2::ManageConnection for ReaderConnectionManager {
        type Connection = ReaderConnection;
        type Error = RedisError;
        fn connect(&self) -> Result<Self::Connection> {
            match self.0.connect() {
                Ok(connection) => Ok(ReaderConnection(connection)),
                Err(err) => Err(err),
            }
        }
        fn is_valid(&self, conn: &mut Self::Connection) -> Result<()> {
            self.0.is_valid(&mut conn.0)
        }
        fn has_broken(&self, conn: &mut Self::Connection) -> bool {
            self.0.has_broken(&mut conn.0)
        }
    }
}

impl Poolable for db::WriterConnection {
    type Manager = db::WriterConnectionManager;
    type Error = DbError<r2d2_redis_cluster::redis_cluster_rs::redis::RedisError>;

    fn pool(config: DatabaseConfig<'_>) -> Result<Pool<Self::Manager>, Self::Error> {
        let manager = Self::Manager::new(config.url).map_err(DbError::Custom)?;
        r2d2::Pool::builder()
            .max_size(config.pool_size)
            .build(manager)
            .map_err(DbError::PoolError)
    }
}
impl Poolable for db::ReaderConnection {
    type Manager = db::ReaderConnectionManager;
    type Error = DbError<r2d2_redis_cluster::redis_cluster_rs::redis::RedisError>;

    fn pool(config: DatabaseConfig<'_>) -> Result<Pool<Self::Manager>, Self::Error> {
        let manager = Self::Manager::new(config.url).map_err(DbError::Custom)?;
        r2d2::Pool::builder()
            .max_size(config.pool_size)
            .build(manager)
            .map_err(DbError::PoolError)
    }
}
