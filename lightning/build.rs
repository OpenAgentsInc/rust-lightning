fn main() {
	if std::env::var_os("CARGO_FEATURE_SIMPLE_CLOSE").is_some() {
		println!("cargo:rustc-cfg=simple_close");
	}
}
