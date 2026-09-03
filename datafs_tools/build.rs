use std::env;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.parent().unwrap();
    let liburing = env::var_os("LIBURING")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env::var_os("HOME").unwrap()).join("dev/liburing"));

    println!(
        "cargo:rustc-link-search=native={}",
        manifest.join(".libbpf").display()
    );
    println!(
        "cargo:rustc-link-search=native={}",
        liburing.join("src").display()
    );
    println!("cargo:rustc-link-lib=static=bpf");
    println!("cargo:rustc-link-lib=static=uring");
    println!("cargo:rustc-link-lib=elf");
    println!("cargo:rustc-link-lib=z");
    println!(
        "cargo:rerun-if-changed={}",
        root.join("include/uapi/linux/datafs.h").display()
    );
}
