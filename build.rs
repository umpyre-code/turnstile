use std::env;
use std::fs;
use std::process::Command;

fn build_openapi_html(out_dir: &str) -> std::io::Result<std::process::ExitStatus> {
    Command::new("yarn")
        .args(&[
            "run",
            "api2html",
            "-l",
            "shell,javascript--nodejs,ruby,python,go",
            "openapi.yaml",
            "-o",
        ])
        .arg(&format!("{}/openapi.html", out_dir))
        .status()
}

fn main() -> std::io::Result<()> {
    let out_dir = env::var("OUT_DIR").unwrap();

    let openapi_html_path = format!("{}/openapi.html", out_dir);

    if let Ok(openapi_html_metadata) = fs::metadata(&openapi_html_path) {
        let openapi_yaml_metadata = fs::metadata("openapi.yaml")?;

        let openapi_html_mtime = openapi_html_metadata.modified().unwrap();
        let openapi_yaml_mtime = openapi_yaml_metadata.modified().unwrap();
        if openapi_yaml_mtime > openapi_html_mtime {
            build_openapi_html(&out_dir)?;
        }
    } else {
        build_openapi_html(&out_dir)?;
    }

    Ok(())
}
