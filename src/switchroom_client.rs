extern crate futures;
extern crate hyper;
extern crate switchroom_grpc;
extern crate tokio_connect;
extern crate tower;
extern crate tower_hyper;
extern crate tower_request_modifier;
extern crate webpki;

use futures::Future;

use crate::config;
use hyper::client::connect::{Destination, HttpConnector};
use instrumented::instrument;
use switchroom_grpc::tower_grpc::{BoxBody, Request};
use tower::MakeService;
use tower_buffer::Buffer;
use tower_hyper::{client, util};
use tower_request_modifier::{Builder, RequestModifier};

#[derive(Clone)]
struct Dst {
    host: String,
    port: i32,
}

pub type Buf =
    Buffer<RequestModifier<tower_hyper::Connection<BoxBody>, BoxBody>, http::Request<BoxBody>>;
pub type RpcClient = switchroom_grpc::proto::client::Switchroom<Buf>;

#[derive(Debug, Fail)]
pub enum SwitchroomError {
    #[fail(display = "Switchroom client connection failure: {}", err)]
    ConnectionFailure { err: String },
    #[fail(
        display = "Switchroom client request failed, code={:?} message={}",
        code, message
    )]
    RequestFailure {
        code: switchroom_grpc::tower_grpc::Code,
        message: String,
    },
    #[fail(display = "Switchroom IO error: {}", err)]
    IoError { err: String },
}

impl From<tower_hyper::client::ConnectError<std::io::Error>> for SwitchroomError {
    fn from(err: tower_hyper::client::ConnectError<std::io::Error>) -> Self {
        SwitchroomError::ConnectionFailure {
            err: err.to_string(),
        }
    }
}

impl From<switchroom_grpc::tower_grpc::Status> for SwitchroomError {
    fn from(err: switchroom_grpc::tower_grpc::Status) -> Self {
        SwitchroomError::RequestFailure {
            code: err.code(),
            message: err.message().to_string(),
        }
    }
}

impl From<std::io::Error> for SwitchroomError {
    fn from(err: std::io::Error) -> Self {
        SwitchroomError::IoError {
            err: err.to_string(),
        }
    }
}

pub struct Client {
    uri: http::Uri,
}

impl Client {
    pub fn new(config: &config::Config) -> Self {
        Client {
            uri: format!("http://{}:{}", config.switchroom.host, config.switchroom.port)
                .parse()
                .unwrap(),
        }
    }

    fn make_service(&self) -> impl Future<Item = RpcClient, Error = SwitchroomError> + Send {
        let uri = self.uri.clone();
        let dst = Destination::try_from_uri(self.uri.clone()).unwrap();
        let connector = util::Connector::new(HttpConnector::new(4));
        let settings = client::Builder::new().http2_only(true).clone();
        let mut make_client = client::Connect::with_builder(connector, settings);

        make_client
            .make_service(dst)
            .map(move |conn| {
                use switchroom_grpc::proto::client::Switchroom;

                let connection = Builder::new().set_origin(uri).build(conn).unwrap();
                let buffer = Buffer::new(connection, 128);

                Switchroom::new(buffer)
            })
            .map_err(SwitchroomError::from)
    }

    #[instrument(INFO)]
    pub fn get_messages(
        &self,
        get_messages_request: switchroom_grpc::proto::GetMessagesRequest,
    ) -> Result<switchroom_grpc::proto::GetMessagesResponse, SwitchroomError> {
        let mut runtime = tokio::runtime::Runtime::new()?;

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .get_messages(Request::new(get_messages_request))
                        .map_err(SwitchroomError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }

        #[instrument(INFO)]
    pub fn send_message(
        &self,
        message: switchroom_grpc::proto::Message,
    ) -> Result<switchroom_grpc::proto::Message, SwitchroomError> {
        let mut runtime = tokio::runtime::Runtime::new()?;

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .send_message(Request::new(message))
                        .map_err(SwitchroomError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }
}
