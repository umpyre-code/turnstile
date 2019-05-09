extern crate futures;
extern crate hyper;
extern crate rolodex_grpc;
extern crate tokio_connect;
extern crate tower;
extern crate tower_hyper;
extern crate tower_request_modifier;
extern crate webpki;

use futures::{Future, Poll};

use crate::config;
use hyper::client::connect::{Destination, HttpConnector};
use instrumented::instrument;
use rolodex_grpc::tower_grpc::{BoxBody, Request};
use std::fs;
use std::io::BufReader;
use std::sync::Arc;
use tokio::executor::DefaultExecutor;
use tokio::net::tcp::TcpStream;
use tower::MakeService;
use tower::Service;
use tower_buffer::Buffer;
use tower_hyper::{client, util};
use tower_request_modifier::{Builder, RequestModifier};

#[derive(Clone)]
struct Dst {
    host: String,
    port: i32,
}

pub type Buf = Buffer<RequestModifier<tower_hyper::Connection<BoxBody>, BoxBody>, http::Request<BoxBody>>;
pub type RpcClient = rolodex_grpc::proto::client::Rolodex<Buf>;

#[derive(Debug, Fail)]
pub enum RolodexError {
    #[fail(display = "Rolodex client connection failure: {}", err)]
    ConnectionFailure { err: String },
    #[fail(
        display = "Rolodex client request failed, code={:?} message={}",
        code, message
    )]
    RequestFailure {
        code: rolodex_grpc::tower_grpc::Code,
        message: String,
    },
}

impl From<tower_hyper::client::ConnectError<std::io::Error>> for RolodexError {
    fn from(err: tower_hyper::client::ConnectError<std::io::Error>) -> Self {
        RolodexError::ConnectionFailure {
            err: err.to_string(),
        }
    }
}

impl From<rolodex_grpc::tower_grpc::Status> for RolodexError {
    fn from(err: rolodex_grpc::tower_grpc::Status) -> Self {
        RolodexError::RequestFailure {
            code: err.code(),
            message: err.message().to_string(),
        }
    }
}

pub struct Client {
    uri: http::Uri,
}

impl Client {
    pub fn new(config: &config::Config) -> Self {
        Client {
            uri: format!("http://{}:{}", config.rolodex.host, config.rolodex.port)
                .parse()
                .unwrap(),
        }
    }

    fn make_service(&self) -> impl Future<Item = RpcClient, Error = RolodexError> + Send {
        let uri = self.uri.clone();
        let dst = Destination::try_from_uri(self.uri.clone()).unwrap();
        let connector = util::Connector::new(HttpConnector::new(4));
        let settings = client::Builder::new().http2_only(true).clone();
        let mut make_client = client::Connect::with_builder(connector, settings);

        make_client
            .make_service(dst)
            .map(move |conn| {
                use rolodex_grpc::proto::client::Rolodex;

                let connection = Builder::new().set_origin(uri).build(conn).unwrap();
                let buffer = Buffer::new(connection, 128);

                Rolodex::new(buffer)
            })
            .map_err(RolodexError::from)
    }

    #[instrument(INFO)]
    pub fn add_user(
        &self,
        new_user_request: rolodex_grpc::proto::NewUserRequest,
    ) -> Result<rolodex_grpc::proto::NewUserResponse, RolodexError> {
        let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .add_user(Request::new(new_user_request))
                        .map_err(RolodexError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }

    #[instrument(INFO)]
    pub fn get_user(
        &self,
        get_user_request: rolodex_grpc::proto::GetUserRequest,
    ) -> Result<rolodex_grpc::proto::GetUserResponse, RolodexError> {
        let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .get_user(Request::new(get_user_request))
                        .map_err(RolodexError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }

    #[instrument(INFO)]
    pub fn authenticate(
        &self,
        auth_request: rolodex_grpc::proto::AuthRequest,
    ) -> Result<rolodex_grpc::proto::AuthResponse, RolodexError> {
        let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .authenticate(Request::new(auth_request))
                        .map_err(RolodexError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }
}

// impl Service<()> for Dst {
//     type Response = TlsStream<TcpStream, ClientSession>;
//     type Error = ::std::io::Error;
//     type Future = Box<Future<Item = Self::Response, Error = ::std::io::Error> + Send>;

//     fn poll_ready(&mut self) -> Poll<(), Self::Error> {
//         Ok(().into())
//     }

//     fn call(&mut self, _: ()) -> Self::Future {
//         use std::net::ToSocketAddrs;

//         let mut pem = BufReader::new(fs::File::open(&config::CONFIG.rolodex.ca_cert_path).unwrap());
//         let mut config = ClientConfig::new();
//         config.root_store.add_pem_file(&mut pem).unwrap();
//         config.set_single_client_cert(
//             load_certs(&config::CONFIG.rolodex.tls_cert_path),
//             load_private_key(&config::CONFIG.rolodex.tls_key_path),
//         );
//         config.alpn_protocols.push(b"h2".to_vec());
//         let config = Arc::new(config);
//         let tls_connector = TlsConnector::from(config);

//         let domain = webpki::DNSNameRef::try_from_ascii_str(&self.host)
//             .unwrap()
//             .to_owned();

//         let mut addresses = format!("{}:{}", self.host, self.port)
//             .to_socket_addrs()
//             .expect("Couldn't resolve rolodex host");

//         let address = addresses
//             .find(|a| match a {
//                 std::net::SocketAddr::V4 { .. } => true,
//                 _ => false,
//             })
//             .expect("No IPV4 address found");

//         let stream = TcpStream::connect(&address).and_then(move |sock| {
//             sock.set_nodelay(true).unwrap();
//             tls_connector.connect(domain.as_ref(), sock)
//         });

//         Box::new(stream)
//     }
// }
