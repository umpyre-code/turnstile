use crate::config;

pub fn invalidate_cdn_cache(path: &str) {
    use std::process::Command;

    let url_maps = &config::CONFIG.gcp.cdn_url_maps;

    for url_map in url_maps.iter() {
        let child = Command::new("gcloud")
            .args(&[
                "compute",
                "url-maps",
                "invalidate-cdn-cache",
                url_map,
                "--path",
                path,
                "--project",
                &config::CONFIG.gcp.project,
                "--async",
            ])
            .spawn()
            .expect("failed to execute gcloud");
        info!("spawned gcloud command, pid: {}", child.id());
    }
}
