use crate::config;
use crate::error::ResponseError;

use instrumented::instrument;
use rocket::response::content;

fn get_google_token(credentials: &str, scopes: Vec<&str>) -> String {
    use yup_oauth2::GetToken;

    let client_secret = yup_oauth2::service_account_key_from_file(credentials).unwrap();
    let mut access = yup_oauth2::ServiceAccountAccess::new(client_secret).build();

    let mut runtime = tokio::runtime::Runtime::new().expect("Unable to create a runtime");

    let tok = runtime
        .block_on(access.token(scopes))
        .expect("couldn't get oauth2 token");

    tok.access_token
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GCSParams<'a> {
    upload_type: &'a str,
    name: &'a str,
}

#[instrument(INFO)]
pub fn get_from_gcs(object: &str) -> Result<reqwest::Response, ResponseError> {
    let url = format!(
        "https://www.googleapis.com/storage/v1/b/{}/o/{}",
        config::CONFIG.service.image_bucket,
        object
    );
    let client = reqwest::Client::new();
    let mut res = client.get(&url).send()?;

    if res.status().is_success() {
        Ok(res)
    } else {
        match res.status() {
            reqwest::StatusCode::NOT_FOUND => Err(ResponseError::not_found()),
            _ => Err(ResponseError::InternalError {
                response: content::Json(
                    json!({
                        "message:": "GCS failure",
                        "response": res.text().unwrap_or_else(|_| "none".to_string())
                    })
                    .to_string(),
                ),
            }),
        }
    }
}

#[instrument(INFO)]
pub fn post_to_gcs(object: &str, data: Vec<u8>) -> Result<(), ResponseError> {
    let token = get_google_token(
        &config::CONFIG.service.image_bucket_credentials,
        vec!["https://www.googleapis.com/auth/devstorage.read_write"],
    );
    let url = format!(
        "https://www.googleapis.com/upload/storage/v1/b/{}/o",
        config::CONFIG.service.image_bucket,
    );
    let params = GCSParams {
        upload_type: "media",
        name: object,
    };
    let client = reqwest::Client::new();
    let mut res = client
        .post(&url)
        .bearer_auth(&token)
        .query(&params)
        .body(reqwest::Body::from(data))
        .send()?;

    if res.status().is_success() {
        Ok(())
    } else {
        Err(ResponseError::InternalError {
            response: content::Json(
                json!({
                    "message:": "GCS failure",
                    "response": res.text().unwrap_or_else(|_| "none".to_string())
                })
                .to_string(),
            ),
        })
    }
}

#[derive(Serialize)]
struct InvalidateCdnCache {
    path: String,
    host: Option<String>,
}

pub fn invalidate_cdn_cache(path: &str) {
    let token = get_google_token(
        &config::CONFIG.service.image_bucket_credentials,
        vec!["https://www.googleapis.com/auth/compute"],
    );
    let client = reqwest::Client::new();

    let url_maps = &config::CONFIG.gcp.cdn_url_maps;

    for url_map in url_maps.iter() {
        let url = format!(
            "https://www.googleapis.com/compute/v1/projects/{}/global/urlMaps/{}/invalidateCache",
            config::CONFIG.gcp.project,
            url_map
        );

        let body = InvalidateCdnCache {
            path: path.into(),
            host: None,
        };

        let res = client
            .post(&url)
            .json(&body)
            .bearer_auth(&token)
            .send()
            .expect("failed to make request");

        if !res.status().is_success() {
            error!("CDN cache invalidation failed: {:?}", res);
        }
    }
}
