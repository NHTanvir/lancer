fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/lancer.ico");
        res.set("FileDescription", "Lancer Web Security Toolkit");
        res.set("ProductName", "Lancer");
        res.set("LegalCopyright", "Lancer Security");
        res.compile().expect("failed to compile Windows resources");
    }
}
