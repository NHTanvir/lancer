fn main() {
    // LANCER_INSTALLER_ZIP is set by build.bat just before invoking `cargo build -p lancer-setup`.
    // It points at the staged zip that contains the binaries + install.ps1 + lancer.ico.
    let zip_path = std::env::var("LANCER_INSTALLER_ZIP")
        .expect("LANCER_INSTALLER_ZIP env var must be set when building lancer-setup");
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest = format!("{out_dir}/lancer-payload.zip");
    std::fs::copy(&zip_path, &dest).expect("failed to copy installer payload");
    println!("cargo:rerun-if-env-changed=LANCER_INSTALLER_ZIP");
    println!("cargo:rerun-if-changed={zip_path}");
}
