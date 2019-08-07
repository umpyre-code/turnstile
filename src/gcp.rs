use crate::config;

pub fn invalidate_cdn_cache(path: &str) {
    use std::io;
    use std::io::Write;
    use std::process::Command;

    let url_maps = &config::CONFIG.gcp.cdn_url_maps;

    for url_map in url_maps.iter() {
        let output = Command::new("gcloud")
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
            .output()
            .expect("failed to execute gcloud");
        io::stdout().write_all(&output.stdout).unwrap();
        io::stderr().write_all(&output.stderr).unwrap();
    }
}
