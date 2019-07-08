use std::env;
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

    build_openapi_html(&out_dir)?;

    // Only run build script if openapi.yaml changed.
    println!("cargo:rerun-if-changed=openapi.yaml");

    Ok(())
}
