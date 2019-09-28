extern crate beancounter_grpc;
extern crate futures;
extern crate hyper;
extern crate tokio_connect;
extern crate tower;
extern crate tower_hyper;
extern crate tower_request_modifier;
extern crate webpki;

use futures::Future;

use crate::config;
use beancounter_grpc::tower_grpc::{BoxBody, Request};
use hyper::client::connect::{Destination, HttpConnector};
use instrumented::instrument;
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
pub type RpcClient = beancounter_grpc::proto::client::BeanCounter<Buf>;

#[derive(Debug, Fail)]
pub enum BeanCounterError {
    #[fail(display = "BeanCounter client connection failure: {}", err)]
    ConnectionFailure { err: String },
    #[fail(
        display = "BeanCounter client request failed, code={:?} message={}",
        code, message
    )]
    RequestFailure {
        code: beancounter_grpc::tower_grpc::Code,
        message: String,
    },
    #[fail(display = "BeanCounter IO error: {}", err)]
    IoError { err: String },
}

impl From<tower_hyper::client::ConnectError<std::io::Error>> for BeanCounterError {
    fn from(err: tower_hyper::client::ConnectError<std::io::Error>) -> Self {
        BeanCounterError::ConnectionFailure {
            err: err.to_string(),
        }
    }
}

impl From<beancounter_grpc::tower_grpc::Status> for BeanCounterError {
    fn from(err: beancounter_grpc::tower_grpc::Status) -> Self {
        BeanCounterError::RequestFailure {
            code: err.code(),
            message: err.message().to_string(),
        }
    }
}

impl From<std::io::Error> for BeanCounterError {
    fn from(err: std::io::Error) -> Self {
        BeanCounterError::IoError {
            err: err.to_string(),
        }
    }
}

pub struct Client {
    uri: http::Uri,
}

macro_rules! with_client {
    ( $svc:expr, $request:path, $payload:expr ) => {
        tokio::runtime::current_thread::Runtime::new()
            .unwrap()
            .block_on(
                $svc.make_service()
                    .and_then(move |mut client: RpcClient| {
                        $request(&mut client, Request::new($payload))
                            .map_err(BeanCounterError::from)
                    })
                    .map(|response| response.get_ref().clone()),
            )
    };
}

impl Client {
    pub fn new(config: &config::Config) -> Self {
        Self {
            uri: format!(
                "http://{}:{}",
                config.beancounter.host, config.beancounter.port
            )
            .parse()
            .unwrap(),
        }
    }

    fn make_service(&self) -> impl Future<Item = RpcClient, Error = BeanCounterError> + Send {
        let uri = self.uri.clone();
        let dst = Destination::try_from_uri(self.uri.clone()).unwrap();
        let connector = util::Connector::new(HttpConnector::new(4));
        let settings = client::Builder::new().http2_only(true).clone();
        let mut make_client = client::Connect::with_builder(connector, settings);

        make_client
            .make_service(dst)
            .map(move |conn| {
                use beancounter_grpc::proto::client::BeanCounter;

                let connection = Builder::new().set_origin(uri).build(conn).unwrap();
                let buffer = Buffer::new(connection, 128);

                BeanCounter::new(buffer)
            })
            .map_err(BeanCounterError::from)
    }

    #[instrument(INFO)]
    pub fn get_balance(
        &self,
        request: beancounter_grpc::proto::GetBalanceRequest,
    ) -> Result<beancounter_grpc::proto::GetBalanceResponse, BeanCounterError> {
        with_client!(self, RpcClient::get_balance, request)
    }

    #[instrument(INFO)]
    pub fn stripe_charge(
        &self,
        request: beancounter_grpc::proto::StripeChargeRequest,
    ) -> Result<beancounter_grpc::proto::StripeChargeResponse, BeanCounterError> {
        with_client!(self, RpcClient::stripe_charge, request)
    }

    #[instrument(INFO)]
    pub fn get_connect_account(
        &self,
        request: beancounter_grpc::proto::GetConnectAccountRequest,
    ) -> Result<beancounter_grpc::proto::GetConnectAccountResponse, BeanCounterError> {
        with_client!(self, RpcClient::get_connect_account, request)
    }

    #[instrument(INFO)]
    pub fn complete_connect_oauth(
        &self,
        request: beancounter_grpc::proto::CompleteConnectOauthRequest,
    ) -> Result<beancounter_grpc::proto::CompleteConnectOauthResponse, BeanCounterError> {
        with_client!(self, RpcClient::complete_connect_oauth, request)
    }

    #[instrument(INFO)]
    pub fn update_connect_prefs(
        &self,
        request: beancounter_grpc::proto::UpdateConnectAccountPrefsRequest,
    ) -> Result<beancounter_grpc::proto::UpdateConnectAccountPrefsResponse, BeanCounterError> {
        with_client!(self, RpcClient::update_connect_account_prefs, request)
    }

    #[instrument(INFO)]
    pub fn connect_payout(
        &self,
        request: beancounter_grpc::proto::ConnectPayoutRequest,
    ) -> Result<beancounter_grpc::proto::ConnectPayoutResponse, BeanCounterError> {
        with_client!(self, RpcClient::connect_payout, request)
    }

    #[instrument(INFO)]
    pub fn add_payment(
        &self,
        request: beancounter_grpc::proto::AddPaymentRequest,
    ) -> Result<beancounter_grpc::proto::AddPaymentResponse, BeanCounterError> {
        with_client!(self, RpcClient::add_payment, request)
    }

    #[instrument(INFO)]
    pub fn settle_payment(
        &self,
        request: beancounter_grpc::proto::SettlePaymentRequest,
    ) -> Result<beancounter_grpc::proto::SettlePaymentResponse, BeanCounterError> {
        with_client!(self, RpcClient::settle_payment, request)
    }

    #[instrument(INFO)]
    pub fn add_promo(
        &self,
        request: beancounter_grpc::proto::AddPromoRequest,
    ) -> Result<beancounter_grpc::proto::AddPromoResponse, BeanCounterError> {
        with_client!(self, RpcClient::add_promo, request)
    }
}
