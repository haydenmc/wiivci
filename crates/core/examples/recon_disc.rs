//! Dev utility: reconstruct the mountable NFS/disc from a WUP package directory, so it can be
//! reopened with `nod` and compared structurally against another disc.
//! Writes <out>/content/hif_%06d.nfs and <out>/code/htk.bin (the layout nod's NFS reader wants).
//! Run: cargo run -p wiivci-core --release --example recon_disc -- <wup_dir> <out_dir> <wiiu_common_key_hex>
use std::path::Path;
use wiivci_core::package::extract::extract_title;
use wiivci_core::package::ticket::decrypt_title_key;
use wiivci_core::package::tmd::parse_content_records;

fn main() {
    let mut a = std::env::args().skip(1);
    let wup = a
        .next()
        .expect("usage: recon_disc <wup_dir> <out_dir> <ckey_hex>");
    let out = a.next().expect("out_dir");
    let ckey_hex = a.next().expect("wiiu common key hex");
    let mut ckey = [0u8; 16];
    for i in 0..16 {
        ckey[i] = u8::from_str_radix(&ckey_hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    let wup = Path::new(&wup);
    let tmd = std::fs::read(wup.join("title.tmd")).expect("title.tmd");
    let tik = std::fs::read(wup.join("title.tik")).expect("title.tik");
    let title_id = u64::from_be_bytes(tik[0x1DC..0x1E4].try_into().unwrap());
    let mut enc_tk = [0u8; 16];
    enc_tk.copy_from_slice(&tik[0x1BF..0x1CF]);
    let title_key = decrypt_title_key(&ckey, title_id, &enc_tk);
    println!("title_id={title_id:016x} title_key={}", hex(&title_key));

    let records = parse_content_records(&tmd).expect("content records");
    let reader = |id: u32| -> wiivci_core::error::Result<Vec<u8>> {
        let up = wup.join(format!("{id:08X}.app"));
        let lo = wup.join(format!("{id:08x}.app"));
        let p = if up.exists() { up } else { lo };
        std::fs::read(&p).map_err(|e| wiivci_core::error::Error::io(&p, e))
    };
    std::fs::create_dir_all(&out).unwrap();
    // Extract everything, including hif_*.nfs (skip nothing).
    extract_title(&records, &title_key, &reader, Path::new(&out), |_| false).expect("extract");
    println!("reconstructed into {out}");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
