extern crate elastic;

use elastic::client::prelude::*;

use crate::config;
use crate::models;

impl From<models::UpdateClientResponse> for ClientProfileDocument {
    fn from(client: models::UpdateClientResponse) -> Self {
        Self {
            client_id: client.client_id,
            full_name: client.full_name,
            handle: client.handle,
        }
    }
}

#[derive(ElasticType, Serialize, Deserialize)]
pub struct ClientProfileDocument {
    #[elastic(client_id)]
    pub client_id: String,
    pub full_name: String,
    pub handle: Option<String>,
}

pub struct ElasticSearchClient {
    client: SyncClient,
}

impl ElasticSearchClient {
    pub fn new() -> Self {
        let builder =
            SyncClientBuilder::new().sniff_nodes(config::CONFIG.elasticsearch.url.as_str());
        Self {
            client: builder.build().unwrap(),
        }
    }

    pub fn create_indexes(&self) {
        use elastic::prelude::StaticIndex;
        if !self
            .client
            .index(ClientProfileDocument::static_index())
            .exists()
            .send()
            .expect("couldn't check for elasticsearch index")
            .exists()
        {
            self.client
                .index(ClientProfileDocument::static_index())
                .create()
                .send()
                .expect("couldn't create elasticsearch index");
        }
    }

    pub fn update(&self, doc: ClientProfileDocument) {
        self.client
            .document::<ClientProfileDocument>()
            .put_mapping()
            .send()
            .expect("failed to put document mapping");
        self.client
            .document()
            .index(doc)
            .send()
            .expect("failed to index doc");
    }
}
