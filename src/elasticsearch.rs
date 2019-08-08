extern crate elastic;

use elastic::client::prelude::*;
use elastic::types::prelude::*;
use instrumented::instrument;
use std::collections::BTreeMap;

use crate::config;
use crate::models;

impl From<models::UpdateClientResponse> for ClientProfileDocument {
    fn from(client: models::UpdateClientResponse) -> Self {
        let handle = client.handle.unwrap_or_else(|| String::from(""));
        Self {
            client_id: client.client_id,
            full_name: client.full_name.clone(),
            handle: handle.clone(),
            suggest: vec![
                Text::<StringMapping>::new(client.full_name),
                Text::<StringMapping>::new(handle),
            ],
        }
    }
}

impl ClientProfileDocument {
    pub fn new(client_id: &str, full_name: &str, handle: &str) -> Self {
        Self {
            client_id: client_id.into(),
            full_name: full_name.into(),
            handle: handle.into(),
            suggest: vec![
                Text::<StringMapping>::new(full_name),
                Text::<StringMapping>::new(handle),
            ],
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct StringMapping;

impl elastic::types::string::text::mapping::TextMapping for StringMapping {
    fn fields() -> Option<BTreeMap<&'static str, StringField>> {
        let mut fields = BTreeMap::new();

        // Add a `completion` suggester as a sub field
        fields.insert(
            "suggest",
            StringField::Completion(ElasticCompletionFieldMapping::default()),
        );

        Some(fields)
    }
}

#[derive(ElasticType, Clone, Debug, Serialize, Deserialize)]
#[elastic(index = "client_profiles")]
pub struct ClientProfileDocument {
    #[elastic(id)]
    pub client_id: String,
    pub full_name: String,
    pub handle: String,
    pub suggest: Vec<Text<StringMapping>>,
}

pub struct ElasticSearchClient {
    client: SyncClient,
}

#[derive(Deserialize, Debug)]
pub struct SuggestResponse<T> {
    took: u64,
    timed_out: bool,
    #[serde(rename = "_shards")]
    shards: elastic::client::responses::common::Shards,
    suggest: SuggestWrapper<T>,
    status: Option<u16>,
}

#[derive(Deserialize, Debug)]
struct SuggestWrapper<T> {
    suggest: Vec<Suggest<T>>,
}

#[derive(Deserialize, Debug)]
pub struct Suggest<T> {
    pub text: String,
    pub offset: i64,
    pub length: i64,
    pub options: Vec<SuggestOption<T>>,
}

#[derive(Deserialize, Debug)]
pub struct SuggestOption<T> {
    #[serde(rename = "_index")]
    index: String,
    #[serde(rename = "_type")]
    ty: String,
    #[serde(rename = "_id")]
    id: String,
    #[serde(rename = "_version")]
    version: Option<u32>,
    #[serde(rename = "_score")]
    score: Option<f32>,
    #[serde(rename = "_source")]
    source: Option<T>,
    #[serde(rename = "_routing")]
    routing: Option<String>,
    highlight: Option<serde_json::Value>,
}

impl<T> elastic::http::receiver::IsOkOnSuccess for SuggestResponse<T> {}

impl ElasticSearchClient {
    pub fn new() -> Self {
        let builder =
            SyncClientBuilder::new().sniff_nodes(config::CONFIG.elasticsearch.url.as_str());
        Self {
            client: builder.build().unwrap(),
        }
    }

    pub fn create_indices(&self) {
        let index_template = serde_json::json!({
          "index_patterns": ["client_profiles"],
          "settings": {
            "number_of_shards": 9,
            "number_of_replicas" : 2
          },
          "mappings": {
            "_source": {
              "enabled": true
            }
          }
        });

        // Apply index template
        self.client
            .request(elastic::endpoints::IndicesPutTemplateRequest::for_name(
                "client_profiles_template",
                index_template,
            ))
            .send()
            .expect("couldn't update index template");

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

    #[instrument(INFO)]
    pub fn search_suggest(
        &self,
        prefix: &str,
    ) -> Result<Vec<ClientProfileDocument>, elastic::Error> {
        let res = self
            .client
            .request(elastic::endpoints::SearchRequest::for_index(
                ClientProfileDocument::static_index(),
                serde_json::json!({
                    "suggest": {
                        "suggest" : {
                            "prefix" : prefix,
                            "completion" : {
                                "field" : "suggest.suggest"
                            }
                        }
                    },
                    // Limit to 20 documents
                    "from": 0,
                    "size": 20,
                }),
            ))
            .send()?
            .into_response::<SuggestResponse<ClientProfileDocument>>()?;

        Ok(res
            .suggest
            .suggest
            .iter()
            .map(|s| s.options.iter())
            .flatten()
            .filter_map(|s| s.source.as_ref())
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_mapping() {
        let mapping = serde_json::to_value(&ClientProfileDocument::index_mapping()).unwrap();

        let expected = serde_json::json!({
            "properties":{
                "client_id":{
                    "fields":{
                        "keyword":{
                            "ignore_above":256,
                            "type":"keyword"
                        }
                    },
                    "type":"text"
                },
                "full_name":{
                    "fields":{
                        "keyword":{
                            "ignore_above":256,
                            "type":"keyword"
                        }
                    },
                    "type":"text"
                },
                "handle":{
                    "fields":{
                        "keyword":{
                            "ignore_above":256,
                            "type":"keyword"
                        }
                    },
                    "type":"text"
                },
                "suggest":{
                    "fields":{
                        "suggest":{
                            "type":"completion"
                        }
                    },
                    "type":"text"
                }
            }
        });

        assert_eq!(expected, mapping);
    }
}
