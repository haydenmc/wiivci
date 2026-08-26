//! Measure how sparsely a Wii disc's data partition is populated: coalesce all FST file extents
//! into contiguous runs (at 64-cluster hash-group granularity) and report how many EGGS ranges a
//! sparse NFS would need (limit is 61) and how many bytes it would store.
//! Run: cargo run -p wiivci-core --release --example frag -- <disc>
use nod::{Disc, OpenOptions, PartitionKind};

const GROUP: u64 = 64 * 0x8000; // 2 MiB hash group

fn main() {
    let path = std::env::args().nth(1).expect("usage: frag <disc>");
    let disc = Disc::new_with_options(
        &path,
        &OpenOptions {
            rebuild_encryption: false,
            ..Default::default()
        },
    )
    .unwrap();
    let is_wii = disc.header().is_wii();
    let part = disc
        .partitions()
        .iter()
        .find(|p| p.kind == PartitionKind::Data)
        .unwrap();
    let data_start_sector = part.data_start_sector as u64;
    let data_bytes = (part.data_end_sector as u64 - part.data_start_sector as u64) * 0x8000;
    let ngroups = data_bytes.div_ceil(GROUP);
    println!(
        "data partition: {} bytes ({:.0} MiB), {} hash-groups",
        data_bytes,
        data_bytes as f64 / 1048576.0,
        ngroups
    );

    let mut part = disc.open_partition_kind(PartitionKind::Data).unwrap();
    let meta = part.meta().unwrap();
    let fst = meta.fst().unwrap();

    // Mark every hash-group that any file touches. Offsets are logical partition-data offsets.
    let mut used = vec![false; ngroups as usize];
    let mut nfiles = 0u64;
    let mut beyond_1_5g = 0u64;
    let mut oob = 0u64;
    let mut top: Vec<(u64, u64, String)> = Vec::new();
    for (_, node, name) in fst.iter() {
        if node.is_dir() {
            continue;
        }
        nfiles += 1;
        let off = node.offset(is_wii);
        let len = node.length();
        top.push((off, len, name.unwrap_or_default().into_owned()));
        if off > 1_500 * 1024 * 1024 {
            beyond_1_5g += 1;
        }
        if len == 0 {
            continue;
        }
        if off >= data_bytes {
            oob += 1;
            continue;
        }
        let first = off / GROUP;
        let last = (off + len - 1) / GROUP;
        for g in first..=last.min(ngroups - 1) {
            used[g as usize] = true;
        }
    }
    // Data-scan: read the actual decrypted bytes of each group and check all-zero (what the NFS
    // sparse writer does). Compares FST-based "used" vs data-based "non-zero".
    {
        use std::io::{Read, Seek, SeekFrom};
        let mut d2 = Disc::new_with_options(
            &path,
            &OpenOptions {
                rebuild_encryption: false,
                ..Default::default()
            },
        )
        .unwrap();
        let data_start = data_start_sector * 0x8000;
        let mut nonzero_groups = 0u64;
        let mut buf = vec![0u8; GROUP as usize];
        for g in 0..ngroups {
            let off = data_start + g * GROUP;
            d2.seek(SeekFrom::Start(off)).unwrap();
            let n = (data_bytes - g * GROUP).min(GROUP) as usize;
            d2.read_exact(&mut buf[..n]).unwrap();
            if buf[..n].iter().any(|&b| b != 0) {
                nonzero_groups += 1;
            }
        }
        println!(
            "DATA-SCAN non-zero groups = {} / {} ({:.0} MiB would be stored by zero-scan sparse)",
            nonzero_groups,
            ngroups,
            nonzero_groups as f64 * 2.0
        );
    }
    top.sort_by_key(|(o, _, _)| std::cmp::Reverse(*o));
    println!("files with offset > 1.5 GiB: {beyond_1_5g}   out-of-range (>= data_bytes): {oob}");
    println!("top 5 files by offset:");
    for (o, l, n) in top.iter().take(5) {
        println!("  off={:.1} MiB len={} {n}", *o as f64 / 1048576.0, l);
    }

    // Always include group 0 (boot.bin/fst region) — it's touched anyway.
    let mut runs = 0u64;
    let mut used_groups = 0u64;
    let mut prev = false;
    for &u in &used {
        if u {
            used_groups += 1;
            if !prev {
                runs += 1;
            }
        }
        prev = u;
    }
    println!("files={nfiles}");
    println!(
        "used groups={} / {}  ({:.0} MiB of real data)",
        used_groups,
        ngroups,
        used_groups as f64 * 2.0
    );
    println!(
        "contiguous runs (= EGGS data ranges needed) = {}  [limit 61, plus 2 for disc header/part table]",
        runs
    );
}
