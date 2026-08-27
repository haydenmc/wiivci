//! Dev utility: build my pipeline's NFS disc for a Wii source, then compare its LOGICAL file
//! contents (by name) against a reference disc (e.g. TeconMoon's reconstructed disc). This
//! isolates data-correctness (do the files' bytes match?) from layout/compaction (offsets differ).
//!
//! Run: cargo run -p wiivci-core --release --example disc_cmp -- <source.rvz> <ref_hif.nfs> <workdir>
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use nod::{Disc, OpenOptions, PartitionKind};
use wiivci_core::disc_patch::plan_disc;
use wiivci_core::input::SourceDisc;
use wiivci_core::nfs::build_nfs;
use wiivci_core::video::VideoPatches;

fn open(path: &Path) -> Disc {
    Disc::new_with_options(
        path,
        &OpenOptions {
            rebuild_encryption: false,
            ..Default::default()
        },
    )
    .expect("open disc")
}

/// name -> (logical offset, length)
fn file_map(disc: &Disc) -> (bool, HashMap<String, (u64, u64)>) {
    let is_wii = disc.header().is_wii();
    let mut part = disc.open_partition_kind(PartitionKind::Data).unwrap();
    let meta = part.meta().unwrap();
    let fst = meta.fst().unwrap();
    let mut m = HashMap::new();
    for (_, node, name) in fst.iter() {
        if node.is_dir() {
            continue;
        }
        let name = name.unwrap_or_default().into_owned();
        m.insert(name, (node.offset(is_wii), node.length()));
    }
    (is_wii, m)
}

fn main() {
    let mut a = std::env::args().skip(1);
    let src = a
        .next()
        .expect("usage: disc_cmp <source> <ref_hif> <workdir>");
    let refhif = a.next().expect("ref_hif");
    let work = a.next().expect("workdir");
    let work = Path::new(&work);
    let content = work.join("content");
    std::fs::create_dir_all(&content).unwrap();

    // Build my disc.
    eprintln!("building my NFS from {src} ...");
    let htk = [0x5Au8; 16];
    let mut source = SourceDisc::open(&src).unwrap();
    let plan = plan_disc(&mut source, &VideoPatches::default(), true, false).unwrap();
    build_nfs(&mut source, &htk, &content, &plan).unwrap();
    let code = work.join("code");
    std::fs::create_dir_all(&code).unwrap();
    std::fs::write(code.join("htk.bin"), htk).unwrap();
    eprintln!("built. opening both discs ...");

    let mine = open(&content.join("hif_000000.nfs"));
    let refd = open(Path::new(&refhif));

    // Partition-level structural summary.
    for (label, d) in [("MINE", &mine), ("REF ", &refd)] {
        for p in d.partitions() {
            if p.kind == PartitionKind::Data {
                let mut part = d.open_partition_kind(PartitionKind::Data).unwrap();
                let m = part.meta().unwrap();
                println!(
                    "{label}: data_start={} data_end={} tmd_len={} tik_len={} h3_len={}",
                    p.data_start_sector,
                    p.data_end_sector,
                    m.raw_tmd.as_ref().map(|v| v.len()).unwrap_or(0),
                    m.raw_ticket.as_ref().map(|v| v.len()).unwrap_or(0),
                    m.raw_h3_table.as_ref().map(|v| v.len()).unwrap_or(0),
                );
            }
        }
    }

    // Compare disc header (boot.bin 0x0..0x440) — game id/magic should match; offsets differ.
    {
        let (_, mut mp) = (0, mine.open_partition_kind(PartitionKind::Data).unwrap());
        let (_, mut rp) = (0, refd.open_partition_kind(PartitionKind::Data).unwrap());
        let mut mb = [0u8; 0x440];
        let mut rb = [0u8; 0x440];
        mp.seek(SeekFrom::Start(0)).unwrap();
        mp.read_exact(&mut mb).unwrap();
        rp.seek(SeekFrom::Start(0)).unwrap();
        rp.read_exact(&mut rb).unwrap();
        println!(
            "boot.bin: gameid_match={} dol_off mine={:#x} ref={:#x} fst_off mine={:#x} ref={:#x} fst_sz mine={:#x} ref={:#x}",
            mb[0..0x20] == rb[0..0x20],
            (u32::from_be_bytes(mb[0x420..0x424].try_into().unwrap()) as u64) << 2,
            (u32::from_be_bytes(rb[0x420..0x424].try_into().unwrap()) as u64) << 2,
            (u32::from_be_bytes(mb[0x424..0x428].try_into().unwrap()) as u64) << 2,
            (u32::from_be_bytes(rb[0x424..0x428].try_into().unwrap()) as u64) << 2,
            (u32::from_be_bytes(mb[0x428..0x42c].try_into().unwrap()) as u64) << 2,
            (u32::from_be_bytes(rb[0x428..0x42c].try_into().unwrap()) as u64) << 2,
        );
    }

    // File-by-file logical content comparison.
    let (_, mmap) = file_map(&mine);
    let (_, rmap) = file_map(&refd);
    println!("files: mine={} ref={}", mmap.len(), rmap.len());

    let mut mp = mine.open_partition_kind(PartitionKind::Data).unwrap();
    let mut rp = refd.open_partition_kind(PartitionKind::Data).unwrap();

    let mut only_mine = 0u64;
    let mut only_ref = 0u64;
    let mut size_mismatch = 0u64;
    let mut content_mismatch = 0u64;
    let mut matched = 0u64;
    let mut mismatch_examples: Vec<String> = Vec::new();

    let mut names: Vec<&String> = mmap.keys().collect();
    names.sort();
    for name in names {
        let (mo, ml) = mmap[name];
        match rmap.get(name) {
            None => only_mine += 1,
            Some(&(ro, rl)) => {
                if ml != rl {
                    size_mismatch += 1;
                    if mismatch_examples.len() < 10 {
                        mismatch_examples.push(format!("SIZE {name}: mine={ml} ref={rl}"));
                    }
                    continue;
                }
                // compare bytes in chunks
                let mut mbuf = vec![0u8; ml.min(8 << 20) as usize];
                let mut rbuf = vec![0u8; mbuf.len()];
                let mut off = 0u64;
                let mut ok = true;
                let mut first_diff = None;
                while off < ml {
                    let n = ((ml - off) as usize).min(mbuf.len());
                    mp.seek(SeekFrom::Start(mo + off)).unwrap();
                    mp.read_exact(&mut mbuf[..n]).unwrap();
                    rp.seek(SeekFrom::Start(ro + off)).unwrap();
                    rp.read_exact(&mut rbuf[..n]).unwrap();
                    if mbuf[..n] != rbuf[..n] {
                        ok = false;
                        for i in 0..n {
                            if mbuf[i] != rbuf[i] {
                                first_diff = Some(off + i as u64);
                                break;
                            }
                        }
                        break;
                    }
                    off += n as u64;
                }
                if ok {
                    matched += 1;
                } else {
                    content_mismatch += 1;
                    if mismatch_examples.len() < 10 {
                        mismatch_examples.push(format!(
                            "CONTENT {name}: first_diff@{first_diff:?} len={ml}"
                        ));
                    }
                }
            }
        }
    }
    for name in rmap.keys() {
        if !mmap.contains_key(name) {
            only_ref += 1;
        }
    }

    println!("\n=== RESULT ===");
    println!("matched(content identical) = {matched}");
    println!("size_mismatch              = {size_mismatch}");
    println!("content_mismatch           = {content_mismatch}");
    println!("only_in_mine               = {only_mine}");
    println!("only_in_ref                = {only_ref}");
    for e in &mismatch_examples {
        println!("  {e}");
    }
}
