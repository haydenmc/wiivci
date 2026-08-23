//! Dev utility: stage a base title and print key reference files.
//! Run: cargo run -p wiivci-core --release --example stage_base -- <base.wua|dir> <out_dir>
use wiivci_core::base::{open_base, REQUIRED_CODE_FILES};

fn main() {
    let mut args = std::env::args().skip(1);
    let base = args.next().expect("usage: stage_base <base> <out_dir>");
    let out = args.next().expect("usage: stage_base <base> <out_dir>");
    std::fs::create_dir_all(&out).unwrap();

    let mut source = open_base(&base).expect("open base");
    let staged = source
        .stage(std::path::Path::new(&out))
        .expect("stage base");

    println!(
        "htk.bin = {}",
        staged
            .htk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    println!("code_dir = {}", staged.code_dir.display());
    for f in REQUIRED_CODE_FILES {
        let p = staged.code_dir.join(f);
        println!(
            "  {f}: {} bytes",
            std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0)
        );
    }
    for name in ["code/app.xml", "code/cos.xml", "meta/meta.xml"] {
        let p = std::path::Path::new(&out).join(name);
        if let Ok(s) = std::fs::read_to_string(&p) {
            println!("\n===== {name} ({} bytes) =====\n{}", s.len(), s);
        }
    }
}
