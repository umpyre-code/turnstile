extern crate futures;
extern crate rolodex_grpc;
extern crate tokio_connect;
extern crate tokio_rustls;
extern crate tower;
extern crate tower_h2;
extern crate tower_reconnect;
extern crate tower_request_modifier;
extern crate webpki;

use crate::certs::{load_certs, load_private_key};

use futures::{Future, Poll};

use crate::config;
use rustls::ClientSession;
use std::fs;
use std::io::BufReader;
use std::sync::Arc;
use tokio::executor::DefaultExecutor;
use tokio::net::tcp::TcpStream;
use tokio_rustls::TlsStream;
use tokio_rustls::{rustls::ClientConfig, TlsConnector};
use tower::MakeService;
use tower::Service;
use tower_buffer::Buffer;
use tower_grpc::{BoxBody, Code, Request, Response, Status};
use tower_h2::client;
use tower_h2::client::{Connect, ConnectError, Connection};
use tower_reconnect::Reconnect;
use tower_request_modifier::{Builder, RequestModifier};

struct Dst;

pub type Buf = Buffer<
    RequestModifier<
        Connection<TlsStream<TcpStream, ClientSession>, DefaultExecutor, BoxBody>,
        BoxBody,
    >,
    http::Request<BoxBody>,
>;
pub type RpcClient = rolodex_grpc::proto::client::Rolodex<Buf>;

pub fn make_client(
    config: &config::Config,
) -> impl Future<Item = RpcClient, Error = ConnectError<std::io::Error>> + Send {
    let uri: http::Uri = format!("https://{}:{}", config.rolodex.host, config.rolodex.port)
        .parse()
        .unwrap();

    let h2_settings = Default::default();
    let service = Dst {};
    let mut make_client = client::Connect::new(service, h2_settings, DefaultExecutor::current());

    let rolodex_client = make_client.make_service(()).map(move |conn| {
        use rolodex_grpc::proto::client::Rolodex;

        let uri = uri;
        let connection = Builder::new().set_origin(uri).build(conn).unwrap();
        let buffer = Buffer::new(connection, 128);

        Rolodex::new(buffer)
    });

    rolodex_client
}

pub struct Error;

pub fn add_user(
    config: &config::Config,
    new_user_request: rolodex_grpc::proto::NewUserRequest,
) -> Result<rolodex_grpc::proto::NewUserResponse, Error> {
    use rolodex_grpc::proto::*;
    use std::cell::RefCell;
    use std::sync::Mutex;
    let result: Arc<Mutex<Option<NewUserResponse>>> = Arc::new(Mutex::new(None));
    let result_inner = result.clone();

    let future = make_client(config)
        .and_then(|mut client: RpcClient| {
            client
                .add_user(Request::new(NewUserRequest {
                    full_name: "What is in a name?".to_string(),
                    email: "hey poo".to_string(),
                    password_hash: "123".to_string(),
                    phone_number: Some(PhoneNumber {
                        country: "US".into(),
                        number: "123".into(),
                    }),
                }))
                .map_err(|e| panic!("gRPC request failed; err={:?}", e))
        })
        .and_then(move |response| {
            error!("RESPONSE = {:?}", response);
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
        None => Err(Error),
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
        let mut pem = BufReader::new(fs::File::open("test/UmpyreAuth.crt").unwrap());
        let mut config = ClientConfig::new();
        config.root_store.add_pem_file(&mut pem).unwrap();
        config.set_single_client_cert(
            load_certs("test/Frontend.crt"),
            load_private_key("test/Frontend.key"),
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
