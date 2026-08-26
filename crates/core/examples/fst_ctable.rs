//! Decode content 0 (the FST) of a WUP package and dump its content table (secondary headers).
//! Run: cargo run -p wiivci-core --release --example fst_ctable -- <wup_dir>
use std::path::Path;
use wiivci_core::package::content_crypto::{decode_hashed, decode_nonhashed};
use wiivci_core::package::fst::Fst;
use wiivci_core::package::tmd::parse_content_records;

const TITLE_KEY: [u8; 16] = [
    0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37,
];

fn read_app(wup: &Path, id: u32) -> Vec<u8> {
    let up = wup.join(format!("{id:08X}.app"));
    let lo = wup.join(format!("{id:08x}.app"));
    std::fs::read(&up).or_else(|_| std::fs::read(&lo)).unwrap()
}

fn main() {
    let wup = std::env::args()
        .nth(1)
        .expect("usage: fst_ctable <wup_dir>");
    let wup = Path::new(&wup);
    let tmd = std::fs::read(wup.join("title.tmd")).unwrap();
    let records = parse_content_records(&tmd).unwrap();
    let fst_rec = records.iter().find(|r| r.index == 0).unwrap();
    let cipher = read_app(wup, fst_rec.id);
    let fst_data = if fst_rec.content_type == 0x2003 {
        decode_hashed(&TITLE_KEY, 0, &cipher)
    } else {
        decode_nonhashed(&TITLE_KEY, 0, &cipher)
    };
    let fst = Fst::parse(&fst_data).expect("parse fst");
    println!(
        "offset_factor={:#x} contents={} nodes={}",
        fst.offset_factor,
        fst.contents.len(),
        fst.nodes.len()
    );
    println!(
        "{:>3} | {:>12} {:>12} | {:>16} {:>10} {:>6}",
        "i", "off_sec", "size_sec", "owner_title_id", "group_id", "flags"
    );
    for (i, c) in fst.contents.iter().enumerate() {
        println!(
            "{i:>3} | {:>12} {:>12} | {:016x} {:>#10x} {:>#6x}",
            c.offset_sectors, c.size_sectors, c.owner_title_id, c.group_id, c.flags
        );
    }
}
