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
        let res: SearchResponse<ClientProfileDocument> = self
            .client
            .search()
            .index(ClientProfileDocument::static_index())
            .body(serde_json::json!({
                "suggest": {
                    "suggest" : {
                        "prefix" : prefix,
                        "completion" : {
                            "field" : "suggest.suggest"
                        }
                    }
                },
                // Limit to 20 results
                "from": 0,
                "size": 20,
            }))
            .send()?;

        Ok(res.documents().cloned().collect())
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
