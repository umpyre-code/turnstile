use crate::config;
use crate::elasticsearch;
use crate::error::ResponseError;
use crate::gcp::*;
use crate::guards;
use crate::models::ImageUploadResponse;
use crate::responders::{Cached, Image, JpegReqwestStream, WebpReqwestStream};
use crate::rolodex_client;

use instrumented::instrument;
use libc::{c_float, c_int, size_t};
use rocket_contrib::json::Json;
use std::collections::HashMap;

pub struct ImageUpload(Vec<u8>);

impl rocket::data::FromDataSimple for ImageUpload {
    type Error = std::io::Error;

    // from https://api.rocket.rs/v0.4/rocket/data/trait.FromDataSimple.html
    // see discussion at https://api.rocket.rs/v0.4/rocket/data/trait.FromData.html#provided-implementations
    #[inline(always)]
    fn from_data(
        _: &rocket::Request,
        data: rocket::Data,
    ) -> rocket::data::Outcome<Self, Self::Error> {
        use std::io::Read;
        const LIMIT: u64 = 10 * 1024 * 1024; // 10MiB
        let mut bytes = Vec::new();
        match data.open().take(LIMIT).read_to_end(&mut bytes) {
            Ok(_) => rocket::Outcome::Success(Self(bytes)),
            Err(e) => rocket::Outcome::Failure((rocket::http::Status::BadRequest, e)),
        }
    }
}

struct Thumbnails<'a> {
    thumbs: HashMap<&'a str, image::DynamicImage>,
}

impl<'a> Thumbnails<'a> {
    fn from_buffer(image: &[u8]) -> Result<Self, ResponseError> {
        use image::*;
        use rayon::prelude::*;

        let img = load_from_memory_with_format(&image, ImageFormat::JPEG)?;

        Ok(Self {
            thumbs: [
                ("big", (img.clone(), 2048u32, 2048u32)),
                ("medium", (img.clone(), 1024u32, 1024u32)),
                ("small", (img.clone(), 256u32, 256u32)),
                ("tiny", (img, 64u32, 64u32)),
            ]
            .par_iter()
            .map(|(key, val)| {
                let (img, width, height): &(DynamicImage, u32, u32) = val;
                let result = img.thumbnail(*width, *height);
                (*key, result)
            })
            .collect(),
        })
    }
}

#[link(name = "webp")]
extern "C" {
    // size_t WebPEncodeBGR(const uint8_t* rgb, int width, int height, int stride, float quality_factor, uint8_t** output);
    fn WebPEncodeBGR(
        rgb: *const u8,
        width: c_int,
        height: c_int,
        stride: c_int,
        quality_factor: c_float,
        output: *mut *mut u8,
    ) -> size_t;
}

fn webp_encode(img: image::ImageBuffer<image::Bgr<u8>, Vec<u8>>) -> Vec<u8> {
    let width = img.width();
    let height = img.height();
    let stride = width * 3;
    let quality: c_float = 80.0;
    let mut output: *mut u8 = std::ptr::null_mut();
    let raw = img.into_raw();
    let mut result: Vec<u8> = vec![];
    unsafe {
        let length = WebPEncodeBGR(
            raw.as_ptr(),
            width as c_int,
            height as c_int,
            stride as c_int,
            quality,
            &mut output,
        );
        // Vec::from_raw_parts will take ownership of the underlying data, so we
        // don't have to explicitly call WebPFree() or free().
        result.append(&mut Vec::from_raw_parts(output, length, length));
    }
    result
}

struct EncodedImages<'a> {
    images: HashMap<&'a str, Vec<u8>>,
}

impl<'a> EncodedImages<'a> {
    fn new(thumbnails: &'a Thumbnails, format: image::ImageFormat) -> Self {
        use rayon::prelude::*;
        match format {
            image::ImageFormat::WEBP => Self {
                images: thumbnails
                    .thumbs
                    .par_iter()
                    .map(|(key, val)| {
                        let vec = webp_encode(val.to_bgr());
                        (*key, vec)
                    })
                    .collect(),
            },
            _ => Self {
                images: thumbnails
                    .thumbs
                    .par_iter()
                    .map(|(key, val)| {
                        let mut vec: Vec<u8> = vec![];
                        val.write_to(&mut vec, format).expect("couldn't encode jpg");
                        (*key, vec)
                    })
                    .collect(),
            },
        }
    }
}

#[instrument(INFO)]
fn encode_image_and_upload(kind: &str, client_id: &str, image: &[u8]) -> Result<(), ResponseError> {
    use rayon::prelude::*;

    let thumbnails = Thumbnails::from_buffer(image)?;
    let mut jpegs = EncodedImages::new(&thumbnails, image::ImageFormat::JPEG);
    let mut webps = EncodedImages::new(&thumbnails, image::ImageFormat::WEBP);

    let prefix = format!("{}/{}/{}", kind, client_id.get(0..2).unwrap(), client_id);

    let (_, mut errors): (Vec<_>, Vec<_>) = webps
        .images
        .par_iter_mut()
        .map(|(key, val)| {
            post_to_gcs(
                &format!("{}/{}.webp", prefix, key),
                val.drain(0..).collect(),
            )
        })
        .partition(Result::is_ok);

    if !errors.is_empty() {
        // Just return the first error and stop
        return errors.pop().unwrap();
    }

    let (_, mut errors): (Vec<_>, Vec<_>) = jpegs
        .images
        .par_iter_mut()
        .map(|(key, val)| post_to_gcs(&format!("{}/{}.jpg", prefix, key), val.drain(0..).collect()))
        .partition(Result::is_ok);

    if !errors.is_empty() {
        // Just return the first error and stop
        return errors.pop().unwrap();
    }

    Ok(())
}

#[post("/img/<kind>/<client_id>", data = "<image>", format = "image/jpeg")]
pub fn post_client_image(
    kind: String,
    client_id: String,
    image: ImageUpload,
    calling_client: guards::Client,
    _ratelimited: guards::RateLimited,
) -> Result<Json<ImageUploadResponse>, ResponseError> {
    // check if calling client is authorized
    if calling_client.client_id != client_id {
        return Err(ResponseError::unauthorized("Not authorized"));
    }

    match kind.as_ref() {
        "avatar" => {
            encode_image_and_upload(&kind, &client_id, &image.0)?;

            // fetch client info
            let rolodex_client = rolodex_client::Client::new(&config::CONFIG);

            // increment avatar version
            rolodex_client.increment_client_avatar(
                rolodex_grpc::proto::IncrementClientAvatarRequest {
                    client_id: calling_client.client_id.clone(),
                    increment_by: 1,
                },
            )?;

            let client = rolodex_client::get_client_for(
                &rolodex_client,
                &calling_client.client_id,
                &calling_client.client_id,
            )?;

            // Update the index in elasticsearch. This is launched on a separate thread
            // so it doesn't block.
            let elastic_doc: elasticsearch::ClientProfileDocument = client.clone().into();
            std::thread::spawn(move || {
                let elastic = elasticsearch::ElasticSearchClient::new();
                elastic.update(elastic_doc);
            });

            let handle = if client.handle.is_empty() {
                None
            } else {
                Some(client.handle)
            };

            let _res = invalidate_cdn_cache_for_client(&client.client_id, &handle);

            Ok(Json(ImageUploadResponse {}))
        }
        _ => Err(ResponseError::bad_request("Invalid 'kind' parameter")),
    }
}

#[get("/img/<kind>/<client_id>/<name>")]
pub fn get_client_image(
    kind: String,
    client_id: String,
    name: String,
    _ratelimited: guards::RateLimited,
) -> Result<Cached<Image>, ResponseError> {
    use rocket::response::Stream;
    if client_id.len() != 32 {
        return Err(ResponseError::not_found("client_id"));
    }

    let object = format!(
        "{}/{}/{}/{}",
        kind,
        client_id.get(0..2).unwrap(),
        client_id,
        name
    );

    let splat: Vec<&str> = name.split('.').collect();
    if splat.len() != 2 {
        return Err(ResponseError::not_found("name"));
    }

    match kind.as_ref() {
        "avatar" => match splat[0] {
            // match first part, should be one of these options
            "big" | "medium" | "small" | "tiny" => match splat[1] {
                // match second part
                "jpg" => Ok(Cached::from(
                    Image::Jpeg(JpegReqwestStream(Stream::from(get_from_gcs(&object)?))),
                    30 * 24 * 3600, // 30 days
                )),
                "webp" => Ok(Cached::from(
                    Image::Webp(WebpReqwestStream(Stream::from(get_from_gcs(&object)?))),
                    30 * 24 * 3600, // 30 days
                )),
                _ => Err(ResponseError::not_found("format")),
            },
            _ => Err(ResponseError::not_found("size")),
        },
        _ => Err(ResponseError::not_found("kind")),
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    fn read_into_vec(name: &str) -> std::io::Result<Vec<u8>> {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open(name)?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        return Ok(data);
    }

    #[test]
    fn test_thumbnail() {
        use std::fs::File;
        use std::io::Write;

        let image = read_into_vec(&format!(
            "{}/src/testdata/myface.jpg",
            env!("CARGO_MANIFEST_DIR"),
        ))
        .expect("couldn't read image file");

        let thumbnails = Thumbnails::from_buffer(&image).expect("couldn't generate thumbnails");

        let jpgs = EncodedImages::new(&thumbnails, image::ImageFormat::JPEG);

        for (key, val) in jpgs.images.iter() {
            let mut f = File::create(format!("{}/{}.jpg", env!("OUT_DIR"), key))
                .expect("couldn't create file");
            f.write(&val).expect("couldn't write to file");
        }

        let webps = EncodedImages::new(&thumbnails, image::ImageFormat::WEBP);

        for (key, val) in webps.images.iter() {
            let mut f = File::create(format!("{}/{}.webp", env!("OUT_DIR"), key))
                .expect("couldn't create file");
            f.write(&val).expect("couldn't write to file");
        }
    }
}
