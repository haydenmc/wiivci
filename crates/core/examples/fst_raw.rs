//! Parse an already-decrypted package FST (e.g. .dev/wup_ref/fst_decrypted.bin) and dump the
//! file -> content mapping. Run: cargo run -p wiivci-core --release --example fst_raw -- <fst.bin>
use wiivci_core::package::fst::{Fst, FstNodeKind};

fn main() {
    let p = std::env::args().nth(1).unwrap();
    let data = std::fs::read(&p).unwrap();
    let fst = Fst::parse(&data).unwrap();
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
    for (i, c) in fst.contents.iter().enumerate() {
        println!(
            "content {i}: group={:#x} owner={:016x} flags={:#x}",
            c.group_id, c.owner_title_id, c.flags
        );
    }
    println!("\nfile -> content (offset within content):");
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
