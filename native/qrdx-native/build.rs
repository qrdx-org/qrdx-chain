// Links the system liboqs: the library the Python node verifies with (oqs-python), so a
// signature is judged the same here as there. QRDX_OQS_LIB_DIR points elsewhere if needed.
fn main() {
    let dir = std::env::var("QRDX_OQS_LIB_DIR").unwrap_or_else(|_| "/usr/local/lib".to_string());
    println!("cargo:rustc-link-search=native={dir}");
    println!("cargo:rustc-link-lib=dylib=oqs");
    println!("cargo:rerun-if-env-changed=QRDX_OQS_LIB_DIR");
}
