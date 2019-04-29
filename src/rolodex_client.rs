extern crate futures;
extern crate rolodex_grpc;
extern crate tokio_connect;
extern crate tokio_rustls;
extern crate tower;
extern crate tower_h2;
extern crate tower_request_modifier;
extern crate webpki;

use crate::certs::{load_certs, load_private_key};

use futures::{Future, Poll};

use crate::config;
use instrumented::instrument;
use std::fs;
use std::io::BufReader;
use std::sync::Arc;
use tokio::executor::DefaultExecutor;
use tokio::net::tcp::TcpStream;
use tokio_rustls::{rustls::ClientConfig, rustls::ClientSession, TlsConnector, TlsStream};
use tower::MakeService;
use tower::Service;
use tower_buffer::Buffer;
use tower_grpc::{BoxBody, Request};
use tower_h2::client;
use tower_h2::client::{ConnectError, Connection};
use tower_request_modifier::{Builder, RequestModifier};

#[derive(Clone)]
struct Dst;

pub type Buf = Buffer<
    RequestModifier<
        Connection<TlsStream<TcpStream, ClientSession>, DefaultExecutor, BoxBody>,
        BoxBody,
    >,
    http::Request<BoxBody>,
>;
pub type RpcClient = rolodex_grpc::proto::client::Rolodex<Buf>;

#[derive(Debug, Fail)]
pub enum RolodexError {
    #[fail(display = "Rolodex client failure")]
    ClientFailure,
}

pub struct Client {
    uri: http::Uri,
    service: Dst,
}

impl Client {
    pub fn new(config: &config::Config) -> Self {
        Client {
            service: Dst {},
            uri: format!("https://{}:{}", config.rolodex.host, config.rolodex.port)
                .parse()
                .unwrap(),
        }
    }

    fn make_service(
        &self,
    ) -> impl Future<Item = RpcClient, Error = ConnectError<std::io::Error>> + Send {
        let uri = self.uri.clone();
        client::Connect::new(
            self.service.clone(),
            Default::default(),
            DefaultExecutor::current(),
        )
        .make_service(())
        .map(move |conn| {
            use rolodex_grpc::proto::client::Rolodex;

            let connection = Builder::new().set_origin(uri).build(conn).unwrap();
            let buffer = Buffer::new(connection, 128);

            Rolodex::new(buffer)
        })
    }

    #[instrument(INFO)]
    pub fn add_user(
        &self,
        new_user_request: rolodex_grpc::proto::NewUserRequest,
    ) -> Result<rolodex_grpc::proto::NewUserResponse, RolodexError> {
        use rolodex_grpc::proto::*;
        use std::sync::Mutex;
        let result: Arc<Mutex<Option<NewUserResponse>>> = Arc::new(Mutex::new(None));
        let result_inner = result.clone();

        let future = self
            .make_service()
            .and_then(move |mut client: RpcClient| {
                client
                    .add_user(Request::new(new_user_request))
                    .map_err(|e| panic!("gRPC request failed; err={:?}", e))
            })
            .and_then(move |response| {
                info!("add_user RESPONSE = {:?}", response);
                result_inner
                    .lock()
                    .unwrap()
                    .replace(response.get_ref().clone());
                Ok(())
            })
            .map_err(|e| {
                error!("add_user ERR = {:?}", e);
            });

        tokio::run(future);

        let guard = result.lock().unwrap();
        match *guard {
            Some(ref res) => Ok(res.clone()),
            None => Err(RolodexError::ClientFailure),
        }
    }

    #[instrument(INFO)]
    pub fn authenticate(
        &self,
        auth_request: rolodex_grpc::proto::AuthRequest,
    ) -> Result<rolodex_grpc::proto::AuthResponse, RolodexError> {
        use rolodex_grpc::proto::*;
        use std::sync::Mutex;
        let result: Arc<Mutex<Option<AuthResponse>>> = Arc::new(Mutex::new(None));
        let result_inner = result.clone();

        let future = self
            .make_service()
            .and_then(move |mut client: RpcClient| {
                client
                    .authenticate(Request::new(auth_request))
                    .map_err(|e| panic!("gRPC request failed; err={:?}", e))
            })
            .and_then(move |response| {
                info!("authenticate RESPONSE = {:?}", response);
                result_inner
                    .lock()
                    .unwrap()
                    .replace(response.get_ref().clone());
                Ok(())
            })
            .map_err(|e| {
                error!("ERR = {:?}", e);
            });

        tokio::run(future);

        let guard = result.lock().unwrap();
        match *guard {
            Some(ref res) => Ok(res.clone()),
            None => Err(RolodexError::ClientFailure),
        }
    }
}

impl Service<()> for Dst {
    type Response = TlsStream<TcpStream, ClientSession>;
    type Error = ::std::io::Error;
    type Future = Box<Future<Item = Self::Response, Error = ::std::io::Error> + Send>;

    fn poll_ready(&mut self) -> Poll<(), Self::Error> {
        Ok(().into())
    }

    fn call(&mut self, _: ()) -> Self::Future {
        let mut pem = BufReader::new(fs::File::open(&config::CONFIG.rolodex.ca_cert_path).unwrap());
        let mut config = ClientConfig::new();
        config.root_store.add_pem_file(&mut pem).unwrap();
        config.set_single_client_cert(
            load_certs(&config::CONFIG.rolodex.tls_cert_path),
            load_private_key(&config::CONFIG.rolodex.tls_key_path),
        );
        config.alpn_protocols.push(b"h2".to_vec());
        let config = Arc::new(config);
        let tls_connector = TlsConnector::from(config);

        let domain = webpki::DNSNameRef::try_from_ascii_str("localhost").unwrap();

        let stream = TcpStream::connect(&([127, 0, 0, 1], 10011).into()).and_then(move |sock| {
            sock.set_nodelay(true).unwrap();
            tls_connector.connect(domain, sock)
        });

        Box::new(stream)
    }
}
