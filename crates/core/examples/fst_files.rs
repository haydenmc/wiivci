//! Dump the package FST (content 0): each file's path -> content index, offset, size.
//! Run: cargo run -p wiivci-core --release --example fst_files -- <wup_dir>
use std::path::Path;
use wiivci_core::package::content_crypto::{decode_hashed, decode_nonhashed};
use wiivci_core::package::fst::{Fst, FstNodeKind};
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
    let wup = std::env::args().nth(1).unwrap();
    let wup = Path::new(&wup);
    let tmd = std::fs::read(wup.join("title.tmd")).unwrap();
    let records = parse_content_records(&tmd).unwrap();
    let fst_rec = records.iter().find(|r| r.index == 0).unwrap();
    let cipher = read_app(wup, fst_rec.id);
    let data = if fst_rec.content_type == 0x2003 {
        decode_hashed(&TITLE_KEY, 0, &cipher)
    } else {
        decode_nonhashed(&TITLE_KEY, 0, &cipher)
    };
    let fst = Fst::parse(&data).unwrap();
    // Reconstruct paths.
    let mut paths = vec![String::new(); fst.nodes.len()];
    let mut stack: Vec<(u32, String)> = Vec::new();
    if let Some(FstNodeKind::Dir { end_index, .. }) = fst.nodes.first().map(|n| &n.kind) {
        stack.push((*end_index, String::new()));
    }
    for (i, node) in fst.nodes.iter().enumerate().skip(1) {
        while let Some(&(end, _)) = stack.last() {
            if i as u32 >= end {
                stack.pop();
            } else {
                break;
            }
        }
        let parent = stack.last().map(|(_, p)| p.as_str()).unwrap_or("");
        let path = if parent.is_empty() {
            node.name.clone()
        } else {
            format!("{parent}/{}", node.name)
        };
        paths[i] = path.clone();
        if let FstNodeKind::Dir { end_index, .. } = node.kind {
            stack.push((end_index, path));
        }
    }
    println!("content-type per content index:");
    for (i, c) in fst.contents.iter().enumerate() {
        let rec = records.iter().find(|r| r.index as usize == i);
        println!(
            "  content {i}: type={:#06x} group={:#x} owner={:016x}",
            rec.map(|r| r.content_type).unwrap_or(0),
            c.group_id,
            c.owner_title_id
        );
    }
    println!("\nfile -> content @offset:");
    let mut rows: Vec<(u16, u64, String, u64)> = Vec::new();
    for (i, node) in fst.nodes.iter().enumerate() {
        if let FstNodeKind::File { size, offset } = node.kind {
            rows.push((node.cluster, offset, paths[i].clone(), size));
        }
    }
    rows.sort();
    for (cluster, offset, path, size) in rows {
        println!("  [c{cluster:>2}] @{offset:>10} {path} ({size})");
    }
}
