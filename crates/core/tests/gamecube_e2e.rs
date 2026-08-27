//! End-to-end GameCube (Nintendont) injection test.
//!
//! Runs the full `pipeline::run` GameCube path — author synthetic disc → NFS → package — using the
//! Rhythm Heaven Fever `.wua` base, the Super Monkey Ball 2 test image, and a real `title.cert`.
//! Ignored by default: it needs the local fixtures plus `WIIU_COMMON_KEY` (like the other
//! cross-validation tests), and reads/writes several GB.
//!
//! Run with:
//! ```sh
//! WIIU_COMMON_KEY=<32-hex> cargo test -p wiivci-core --release --test gamecube_e2e -- --ignored
//! ```

use std::path::Path;

use wiivci_core::base::open_base;
use wiivci_core::keys::WiiUCommonKey;
use wiivci_core::nincfg::{Language, VideoMode};
use wiivci_core::package::cert::CertChain;
use wiivci_core::pipeline::{self, Config, GameCubeOptions, Region};
use wiivci_core::video::VideoPatches;

#[test]
#[ignore = "needs .wua base, .dev/wup_ref/title.cert and WIIU_COMMON_KEY; reads/writes several GB"]
fn gamecube_injection_produces_package_and_nincfg() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = root.join("test_titles/Super Monkey Ball 2 (USA).rvz");
    let base_wua = root.join("test_titles/Rhythm Heaven Fever[00050000101B0700][USA][v0].wua");
    let cert_path = root.join(".dev/wup_ref/title.cert");

    let key_hex = match std::env::var("WIIU_COMMON_KEY") {
        Ok(k) => k,
        Err(_) => {
            eprintln!(
                "skipping gamecube_injection_produces_package_and_nincfg: WIIU_COMMON_KEY not present"
            );
            return;
        }
    };
    for p in [&input, &base_wua, &cert_path] {
        if !p.exists() {
            eprintln!(
                "skipping gamecube_injection_produces_package_and_nincfg: {} not present",
                p.display()
            );
            return;
        }
    }

    let wiiu_common_key = WiiUCommonKey::parse(key_hex.trim().as_bytes()).unwrap();
    let cert = CertChain::load(&cert_path).unwrap();
    let base = open_base(&base_wua).unwrap();

    let out_dir = tempfile::tempdir().unwrap();
    let out = out_dir.path().join("pkg");
    let work = tempfile::tempdir().unwrap();

    // A stand-in Nintendont boot.dol (contents don't affect packaging/validation).
    let nintendont_dol: Vec<u8> = (0..64 * 1024u32).map(|i| (i ^ 0x37) as u8).collect();

    let config = Config {
        input,
        base,
        out: out.clone(),
        wiiu_common_key,
        cert,
        title: Some("Super Monkey Ball 2".into()),
        icon_png: None,
        boot_tv_png: None,
        boot_drc_png: None,
        region: Region::Usa,
        gamepad: true,
        online: false,
        video: VideoPatches::default(),
        skip_gaps: true,
        trim_zeros: false,
        gamecube: Some(GameCubeOptions {
            nintendont_dol,
            apploader: Vec::new(),
            widescreen: true,
            language: Language::Auto,
            video_mode: VideoMode::Auto,
            memcard_emu: true,
            cheat_path: None,
        }),
    };

    let summary = pipeline::run(config, work.path()).unwrap();
    assert!(
        summary.package.content_count > 0,
        "package must have contents"
    );

    // The nincfg.bin is written next to the output package.
    let nincfg = out.parent().unwrap().join("nincfg.bin");
    assert!(
        nincfg.exists(),
        "nincfg.bin must be written beside the output"
    );
    let cfg = std::fs::read(&nincfg).unwrap();
    assert_eq!(cfg.len(), 0x222, "nincfg.bin is a v10 record");
    assert_eq!(&cfg[0..4], &[0x01, 0x07, 0x0C, 0xF6], "nincfg magic");

    // The output package exists with the expected WUP files.
    assert!(out.join("title.tmd").exists());
    assert!(out.join("title.tik").exists());
    assert!(out.join("title.cert").exists());
}
