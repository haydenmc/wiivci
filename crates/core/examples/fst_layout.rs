//! Dev utility: report the data-partition file layout of a Wii disc.
//! Prints partition data size vs. the highest file end offset (to distinguish
//! "trailing padding only" from "gap with files near the end").
//! Run: cargo run -p wiivci-core --release --example fst_layout -- <disc>
use nod::{Disc, OpenOptions, PartitionKind, SECTOR_SIZE};

fn main() {
    let path = std::env::args().nth(1).expect("usage: fst_layout <disc>");
    let options = OpenOptions {
        rebuild_encryption: false,
        ..Default::default()
    };
    let disc = Disc::new_with_options(&path, &options).expect("open");
    let is_wii = disc.header().is_wii();
    println!("is_wii={is_wii} disc_size={}", disc.disc_size());
    for p in disc.partitions() {
        println!(
            "partition idx={} kind={:?} start_sector={} data_start={} data_end={} data_bytes={}",
            p.index,
            p.kind,
            p.start_sector,
            p.data_start_sector,
            p.data_end_sector,
            (p.data_end_sector as u64 - p.data_start_sector as u64) * SECTOR_SIZE as u64
        );
    }
    let mut part = disc
        .open_partition_kind(PartitionKind::Data)
        .expect("data part");
    let meta = part.meta().expect("meta");
    let fst = meta.fst().expect("fst");
    let mut max_end: u64 = 0;
    let mut max_name = String::new();
    let mut count = 0u64;
    for (_, node, name) in fst.iter() {
        if node.is_dir() {
            continue;
        }
        count += 1;
        let off = node.offset(is_wii);
        let len = node.length();
        let end = off + len;
        if end > max_end {
            max_end = end;
            max_name = name.unwrap_or_default().into_owned();
        }
    }
    println!("files={count}");
    println!(
        "highest file end (logical partition offset) = {max_end} bytes = {:.1} MiB  ({max_name})",
        max_end as f64 / (1024.0 * 1024.0)
    );
}
