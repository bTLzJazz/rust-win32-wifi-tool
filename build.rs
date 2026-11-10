fn main() {
    println!("cargo:rerun-if-changed=app.manifest");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
    {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("app.manifest");
        println!("cargo:rustc-link-arg-bin=wifi_tool=/MANIFEST:EMBED");
        println!(
            "cargo:rustc-link-arg-bin=wifi_tool=/MANIFESTINPUT:{}",
            manifest.display()
        );
    }
}
