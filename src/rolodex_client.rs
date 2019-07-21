extern crate futures;
extern crate hyper;
extern crate rolodex_grpc;
extern crate tokio_connect;
extern crate tower;
extern crate tower_hyper;
extern crate tower_request_modifier;
extern crate webpki;

use futures::Future;

use crate::config;
use hyper::client::connect::{Destination, HttpConnector};
use instrumented::instrument;
use rolodex_grpc::tower_grpc::{BoxBody, Request};
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
    #[fail(display = "Rolodex IO error: {}", err)]
    IoError { err: String },
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

impl From<std::io::Error> for RolodexError {
    fn from(err: std::io::Error) -> Self {
        RolodexError::IoError {
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
    pub fn add_client(
        &self,
        new_client_request: rolodex_grpc::proto::NewClientRequest,
    ) -> Result<rolodex_grpc::proto::NewClientResponse, RolodexError> {
        let mut runtime = tokio::runtime::current_thread::Runtime::new()?;

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .add_client(Request::new(new_client_request))
                        .map_err(RolodexError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }

    #[instrument(INFO)]
    pub fn get_client(
        &self,
        get_client_request: rolodex_grpc::proto::GetClientRequest,
    ) -> Result<rolodex_grpc::proto::GetClientResponse, RolodexError> {
        let mut runtime = tokio::runtime::current_thread::Runtime::new()?;

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .get_client(Request::new(get_client_request))
                        .map_err(RolodexError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }

    #[instrument(INFO)]
    pub fn auth_handshake(
        &self,
        auth_request: rolodex_grpc::proto::AuthHandshakeRequest,
    ) -> Result<rolodex_grpc::proto::AuthHandshakeResponse, RolodexError> {
        let mut runtime = tokio::runtime::current_thread::Runtime::new()?;

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .auth_handshake(Request::new(auth_request))
                        .map_err(RolodexError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }

    #[instrument(INFO)]
    pub fn auth_verify(
        &self,
        auth_request: rolodex_grpc::proto::AuthVerifyRequest,
    ) -> Result<rolodex_grpc::proto::AuthVerifyResponse, RolodexError> {
        let mut runtime = tokio::runtime::current_thread::Runtime::new()?;

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .auth_verify(Request::new(auth_request))
                        .map_err(RolodexError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }

    #[instrument(INFO)]
    pub fn update_client(
        &self,
        update_request: rolodex_grpc::proto::UpdateClientRequest,
    ) -> Result<rolodex_grpc::proto::UpdateClientResponse, RolodexError> {
        let mut runtime = tokio::runtime::current_thread::Runtime::new()?;

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .update_client(Request::new(update_request))
                        .map_err(RolodexError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }

    #[instrument(INFO)]
    pub fn update_client_password(
        &self,
        update_request: rolodex_grpc::proto::UpdateClientPasswordRequest,
    ) -> Result<rolodex_grpc::proto::UpdateClientPasswordResponse, RolodexError> {
        let mut runtime = tokio::runtime::current_thread::Runtime::new()?;

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .update_client_password(Request::new(update_request))
                        .map_err(RolodexError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }

    #[instrument(INFO)]
    pub fn update_client_email(
        &self,
        update_request: rolodex_grpc::proto::UpdateClientEmailRequest,
    ) -> Result<rolodex_grpc::proto::UpdateClientEmailResponse, RolodexError> {
        let mut runtime = tokio::runtime::current_thread::Runtime::new()?;

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .update_client_email(Request::new(update_request))
                        .map_err(RolodexError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }

    #[instrument(INFO)]
    pub fn update_client_phone_number(
        &self,
        update_request: rolodex_grpc::proto::UpdateClientPhoneNumberRequest,
    ) -> Result<rolodex_grpc::proto::UpdateClientPhoneNumberResponse, RolodexError> {
        let mut runtime = tokio::runtime::current_thread::Runtime::new()?;

        runtime.block_on(
            self.make_service()
                .and_then(move |mut client: RpcClient| {
                    client
                        .update_client_phone_number(Request::new(update_request))
                        .map_err(RolodexError::from)
                })
                .map(|response| response.get_ref().clone()),
        )
    }
}
