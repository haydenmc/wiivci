//! Repackage an already-staged build tree (code/content/meta) through the CURRENT build_package,
//! for isolating packaging structure from disc/game data. Uses the dummy title key (0x1337..).
//! Run: cargo run -p wiivci-core --release --example repackage -- <staged_dir> <out> <ckey_hex> <cert_path> <title_id_hex>
use std::path::Path;
use wiivci_core::package::cert::CertChain;
use wiivci_core::package::{build_package, PackageParams};

const TITLE_KEY: [u8; 16] = [
    0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37,
];

fn hex16(s: &str) -> [u8; 16] {
    let mut k = [0u8; 16];
    for i in 0..16 {
        k[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    k
}

fn main() {
    let mut a = std::env::args().skip(1);
    let staged = a.next().unwrap();
    let out = a.next().unwrap();
    let ckey = hex16(&a.next().unwrap());
    let cert_path = a.next().unwrap();
    let title_id = u64::from_str_radix(&a.next().unwrap(), 16).unwrap();

    let cert = CertChain::load(Path::new(&cert_path)).expect("cert");
    let params = PackageParams {
        title_id,
        group_id: (title_id & 0xFFFF) as u16,
        wiiu_common_key: ckey,
        title_key: TITLE_KEY,
        cert: &cert,
    };
    let stats = build_package(Path::new(&staged), Path::new(&out), &params).expect("build_package");
    println!(
        "packaged {} contents, {} bytes into {out}",
        stats.content_count, stats.total_content_bytes
    );
}
