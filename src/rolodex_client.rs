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
use tower_grpc::Request;
use tower_h2::client;

struct Dst;

pub fn run() {
    let uri: http::Uri = format!("https://localhost:10011").parse().unwrap();

    let h2_settings = Default::default();
    let mut make_client = client::Connect::new(Dst {}, h2_settings, DefaultExecutor::current());

    let say_hello = make_client
        .make_service(())
        .map(move |conn| {
            use rolodex_grpc::proto::client::Rolodex;

            let conn = tower_request_modifier::Builder::new()
                .set_origin(uri)
                .build(conn)
                .unwrap();

            Rolodex::new(conn)
        })
        .and_then(|mut client| {
            use rolodex_grpc::proto::NewUser;

            client
                .add_user(Request::new(NewUser {
                    name: "What is in a name?".to_string(),
                }))
                .map_err(|e| panic!("gRPC request failed; err={:?}", e))
        })
        .and_then(|response| {
            error!("RESPONSE = {:?}", response);
            Ok(())
        })
        .map_err(|e| {
            error!("ERR = {:?}", e);
        });

    tokio::run(say_hello);
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
