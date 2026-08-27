//! End-to-end injection pipeline: Wii disc + base title → installable WUP package.
//!
//! Steps:
//! 1. open the source disc ([`crate::input`]); `nod` decrypts Wii partitions internally;
//! 2. stage the base title into a build directory ([`crate::base`]);
//! 3. convert the disc to NFS under `content/` ([`crate::nfs`]);
//! 4. drop in the game's `rvlt.tik`/`rvlt.tmd` and fakesign-patch `fw.img`;
//! 5. regenerate `code/app.xml`, `meta/meta.xml` and the boot textures ([`crate::meta`],
//!    [`crate::assets`]);
//! 6. package it all into `title.tmd`/`tik`/`cert` + `.app`/`.h3` ([`crate::package`]).

use std::path::{Path, PathBuf};

use crate::assets::images::{png_to_tga, BootTexture};
use crate::assets::{artrepo, gametdb};
use crate::base::BaseSource;
use crate::disc_patch;
use crate::error::{Error, Result};
use crate::fwimg;
use crate::input::{GcImage, SourceDisc};
use crate::keys::WiiUCommonKey;
use crate::meta::appxml;
use crate::meta::metaxml::{patch as patch_meta, MetaOptions};
use crate::meta::titleid;
use crate::nfs::build_nfs;
use crate::nincfg::{self, NincfgOptions};
use crate::package::cert::CertChain;
use crate::package::{build_package, PackageParams, PackageStats};
use crate::video::VideoPatches;
use crate::wii_author::{self, GcDiscInputs};

/// Fixed plaintext title key used to encrypt content (stored, encrypted, in the ticket — its
/// value is arbitrary, matching the convention of the reference tools).
const TITLE_KEY: [u8; 16] = [
    0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37, 0x13, 0x37,
];

/// Region code written to `meta.xml` (bitmask: 1=JP, 2=US, 4=EU).
#[derive(Clone, Copy, Debug)]
pub enum Region {
    /// Japan.
    Japan,
    /// USA.
    Usa,
    /// Europe.
    Europe,
}

impl Region {
    fn code(self) -> u32 {
        match self {
            Region::Japan => 1,
            Region::Usa => 2,
            Region::Europe => 4,
        }
    }
}

/// Configuration for a single injection.
pub struct Config {
    /// Source Wii disc image (ISO/RVZ/…).
    pub input: PathBuf,
    /// Base title source (local `.wua`/directory, or an NUS download).
    pub base: Box<dyn BaseSource>,
    /// Output directory for the WUP package.
    pub out: PathBuf,
    /// Wii U common key (validated).
    pub wiiu_common_key: WiiUCommonKey,
    /// Certificate chain (`title.cert`).
    pub cert: CertChain,
    /// Override title string; if `None`, looked up on GameTDB.
    pub title: Option<String>,
    /// Optional PNG artwork overrides.
    pub icon_png: Option<PathBuf>,
    /// Optional TV boot image PNG.
    pub boot_tv_png: Option<PathBuf>,
    /// Optional GamePad boot image PNG.
    pub boot_drc_png: Option<PathBuf>,
    /// meta.xml region.
    pub region: Region,
    /// Whether the GamePad is usable (`drc_use`).
    pub gamepad: bool,
    /// Fetch missing art/title from online services.
    pub online: bool,
    /// Optional `main.dol` video patches (flicker filter / dithering). Wii path only.
    pub video: VideoPatches,
    /// Store the data partition sparsely by skipping inter-file gaps (normally `true`). When `false`
    /// the whole partition is stored. Wii path only.
    pub skip_gaps: bool,
    /// Also skip storing FST files whose entire content is zero (dummy/padding files); normally
    /// `false`. Wii path only. See [`crate::input::SourceDisc::used_data_group_runs`].
    pub trim_zeros: bool,
    /// When `Some`, the input is a GameCube image and is injected via Nintendont with these
    /// options (see [`run_gamecube`]). When `None`, the input is treated as a Wii disc.
    pub gamecube: Option<GameCubeOptions>,
}

/// Options for a GameCube (Nintendont) injection.
pub struct GameCubeOptions {
    /// Nintendont's `boot.dol`, used as the synthetic disc's `main.dol`.
    pub nintendont_dol: Vec<u8>,
    /// The Wii apploader placed in the synthetic disc. May be empty (the output then validates but
    /// will not boot on hardware — a real apploader is required for that).
    pub apploader: Vec<u8>,
    /// Force 16:9 in the generated `nincfg.bin`.
    pub widescreen: bool,
    /// GameCube language for `nincfg.bin`.
    pub language: nincfg::Language,
    /// Forced video mode for `nincfg.bin`.
    pub video_mode: nincfg::VideoMode,
    /// Emulate a memory card.
    pub memcard_emu: bool,
    /// Optional Gecko cheat file path (on SD) recorded in `nincfg.bin`.
    pub cheat_path: Option<String>,
}

/// Result of an injection.
#[derive(Debug, Clone)]
pub struct Summary {
    /// The derived Wii U title id.
    pub title_id: u64,
    /// The 6-character source game id.
    pub game_id: String,
    /// The resolved title string.
    pub title: String,
    /// Package statistics.
    pub package: PackageStats,
    /// Output directory.
    pub out: PathBuf,
}

/// Run the injection described by `config`, using `work_dir` as scratch space for the staged
/// build tree. `work_dir` should be empty; callers typically pass a fresh temp directory.
pub fn run(mut config: Config, work_dir: &Path) -> Result<Summary> {
    if config.gamecube.is_some() {
        return run_gamecube(config, work_dir);
    }

    log::info!("opening source disc {}", config.input.display());
    let mut source = SourceDisc::open(&config.input)?;
    let game_id = source.game_id_str();
    let disc4 = source.disc_id4();
    let ids = titleid::derive(disc4);

    // 1. Stage the base into work_dir/{code,content,meta}.
    log::info!("staging base title");
    let staged = config.base.stage(work_dir)?;

    // 2. Plan the whole-disc hash rebuild (RVZ/WIA zero the per-cluster hashes) plus any
    //    main.dol video patches (see crate::disc_patch).
    let plan = disc_patch::plan_disc(
        &mut source,
        &config.video,
        config.skip_gaps,
        config.trim_zeros,
    )?;

    // 3. Convert the disc to NFS under content/, rebuilding the Wii hash tree.
    log::info!("building NFS (this reads the whole disc)…");
    let nfs_stats = build_nfs(&mut source, &staged.htk, &staged.content_dir, &plan)?;
    log::info!(
        "NFS: {} file(s), {} bytes",
        nfs_stats.file_count,
        nfs_stats.total_bytes
    );

    // 4. Game ticket/TMD become rvlt.tik / rvlt.tmd. Both are fakesigned (RSA signature zeroed):
    //    fw.img's signature check is patched to accept a zeroed signature, and rejects the disc's
    //    real signature — so an unmodified ticket/TMD boots the framework but hangs the emulator.
    let mut rvlt_tik = source.raw_ticket().to_vec();
    fakesign(&mut rvlt_tik);
    std::fs::write(staged.code_dir.join("rvlt.tik"), &rvlt_tik)
        .map_err(|e| Error::io(staged.code_dir.join("rvlt.tik"), e))?;
    let mut rvlt_tmd = source.raw_tmd().to_vec();
    if let Some(content_hash) = plan.rvlt_content_hash {
        // Also updates the content hash to the rebuilt H3 table, and zeroes the signature.
        update_rvlt_tmd(&mut rvlt_tmd, &content_hash);
    } else {
        fakesign(&mut rvlt_tmd);
    }
    std::fs::write(staged.code_dir.join("rvlt.tmd"), &rvlt_tmd)
        .map_err(|e| Error::io(staged.code_dir.join("rvlt.tmd"), e))?;

    // 5. Fakesign-patch fw.img so the (fakesigned) title is accepted.
    fwimg::patch_file(&staged.code_dir.join("fw.img"), fwimg::FAKESIGN_PATCHES)?;

    // 6. Metadata: app.xml + meta.xml.
    std::fs::write(staged.code_dir.join("app.xml"), appxml::generate(&ids))
        .map_err(|e| Error::io(staged.code_dir.join("app.xml"), e))?;

    let title = resolve_title(&config, &game_id);
    let meta_path = staged.meta_dir.join("meta.xml");
    let base_meta = std::fs::read_to_string(&meta_path).map_err(|e| Error::io(&meta_path, e))?;
    let patched = patch_meta(
        &base_meta,
        &MetaOptions {
            ids: &ids,
            long_name: &title,
            short_name: &title,
            publisher: "",
            region: config.region.code(),
            drc_use: config.gamepad,
        },
    )?;
    std::fs::write(&meta_path, patched).map_err(|e| Error::io(&meta_path, e))?;

    // 7. Boot textures (icon / TV / DRC).
    resolve_textures(&config, "wii", &game_id, &staged.meta_dir)?;

    // 8. Package.
    log::info!("packaging WUP into {}", config.out.display());
    let params = PackageParams {
        title_id: ids.title_id,
        group_id: (ids.group_id & 0xFFFF) as u16,
        wiiu_common_key: config.wiiu_common_key.0,
        title_key: TITLE_KEY,
        cert: &config.cert,
    };
    let package = build_package(work_dir, &config.out, &params)?;

    Ok(Summary {
        title_id: ids.title_id,
        game_id,
        title,
        package,
        out: config.out.clone(),
    })
}

/// Run a GameCube injection: author a synthetic Wii disc that boots Nintendont (with the game as
/// `files/game.iso`), then reuse the Wii pipeline's NFS/packaging back half. Also emits an
/// `nincfg.bin` next to the output for the user's SD card.
fn run_gamecube(mut config: Config, work_dir: &Path) -> Result<Summary> {
    let gc_opts = config
        .gamecube
        .take()
        .expect("run() dispatches here only when gamecube options are present");

    log::info!("opening GameCube image {}", config.input.display());
    let mut gc = GcImage::open(&config.input)?;
    let game_id = gc.game_id_str();
    let game_id4 = gc.disc_id4();
    let ids = titleid::derive(game_id4);
    let iso_size = gc.iso_size();

    // 1. Stage the base title.
    log::info!("staging base title");
    let staged = config.base.stage(work_dir)?;

    // 2. Author the synthetic Wii disc (Nintendont as main.dol + the GameCube image as game.iso).
    if gc_opts.apploader.is_empty() {
        log::warn!(
            "no apploader supplied: the package will validate but will NOT boot on hardware \
             (supply one with --apploader)"
        );
    }
    let disc_title = config.title.clone().unwrap_or_else(|| game_id.clone());
    let disc_path = work_dir.join("gc_disc.img");
    log::info!(
        "authoring synthetic Wii disc (embedding {} MiB game.iso)…",
        iso_size / (1024 * 1024)
    );
    let inputs = GcDiscInputs {
        game_id: gc.game_id(),
        disc_title: &disc_title,
        main_dol: &gc_opts.nintendont_dol,
        apploader: &gc_opts.apploader,
        title_id: ids.title_id,
    };
    let mut authored = wii_author::author_gc_disc(gc.iso_stream(), iso_size, &inputs, &disc_path)?;

    // 3. Convert to NFS under content/, rebuilding the Wii hash tree.
    log::info!("building NFS (this reads the whole disc)…");
    let plan = authored.plan.clone();
    let nfs_stats = build_nfs(&mut authored, &staged.htk, &staged.content_dir, &plan)?;
    log::info!(
        "NFS: {} file(s), {} bytes",
        nfs_stats.file_count,
        nfs_stats.total_bytes
    );

    // The synthetic disc image (a full-disc-size scratch file) is only needed to build the NFS;
    // remove it now instead of leaving it in work_dir alongside the NFS content, which would
    // otherwise roughly double peak scratch usage for the rest of the build.
    match std::fs::metadata(&disc_path).and_then(|m| {
        let len = m.len();
        std::fs::remove_file(&disc_path).map(|()| len)
    }) {
        Ok(freed) => log::info!(
            "removed scratch {} ({:.1} MiB freed)",
            disc_path.display(),
            freed as f64 / (1024.0 * 1024.0)
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::io(&disc_path, e)),
    }

    // 4. Write the synthetic disc's Wii ticket/TMD as rvlt.tik / rvlt.tmd.
    let tik_path = staged.code_dir.join("rvlt.tik");
    std::fs::write(&tik_path, &authored.rvlt_ticket).map_err(|e| Error::io(&tik_path, e))?;
    let tmd_path = staged.code_dir.join("rvlt.tmd");
    std::fs::write(&tmd_path, &authored.rvlt_tmd).map_err(|e| Error::io(&tmd_path, e))?;

    // 5. Patch fw.img: fakesign + homebrew (AHBPROT/MEMPROT) so Nintendont gets hardware access.
    fwimg::patch_file(&staged.code_dir.join("fw.img"), fwimg::HOMEBREW_PATCHES)?;

    // 6. Metadata: app.xml + meta.xml.
    std::fs::write(staged.code_dir.join("app.xml"), appxml::generate(&ids))
        .map_err(|e| Error::io(staged.code_dir.join("app.xml"), e))?;

    let title = resolve_title(&config, &game_id);
    let meta_path = staged.meta_dir.join("meta.xml");
    let base_meta = std::fs::read_to_string(&meta_path).map_err(|e| Error::io(&meta_path, e))?;
    let patched = patch_meta(
        &base_meta,
        &MetaOptions {
            ids: &ids,
            long_name: &title,
            short_name: &title,
            publisher: "",
            region: config.region.code(),
            drc_use: config.gamepad,
        },
    )?;
    std::fs::write(&meta_path, patched).map_err(|e| Error::io(&meta_path, e))?;

    // 7. Boot textures (GameCube art repository; UWUVCI-IMAGES keys GameCube under "gcn").
    resolve_textures(&config, "gcn", &game_id, &staged.meta_dir)?;

    // 8. Package.
    log::info!("packaging WUP into {}", config.out.display());
    let params = PackageParams {
        title_id: ids.title_id,
        group_id: (ids.group_id & 0xFFFF) as u16,
        wiiu_common_key: config.wiiu_common_key.0,
        title_key: TITLE_KEY,
        cert: &config.cert,
    };
    let package = build_package(work_dir, &config.out, &params)?;

    // 9. Emit nincfg.bin next to the output package (it belongs at the SD-card root, not in the WUP).
    let nincfg = nincfg::generate(&NincfgOptions {
        game_id: game_id4,
        widescreen: gc_opts.widescreen,
        language: gc_opts.language,
        video_mode: gc_opts.video_mode,
        memcard_emu: gc_opts.memcard_emu,
        cheat_path: gc_opts.cheat_path.clone(),
        ..Default::default()
    });
    // Resolve --out to an absolute path first: a bare relative `--out` (e.g. `MyGame`, with no
    // parent component) would otherwise leave `parent()` ambiguous, landing nincfg.bin wherever
    // the process happens to be running from rather than reliably next to the output.
    let out_abs = std::path::absolute(&config.out).map_err(|e| Error::io(&config.out, e))?;
    let nincfg_path = out_abs
        .parent()
        .unwrap_or(out_abs.as_path())
        .join("nincfg.bin");
    if nincfg_path.exists() {
        log::warn!(
            "overwriting existing {} (each build's nincfg.bin is game-specific)",
            nincfg_path.display()
        );
    }
    std::fs::write(&nincfg_path, nincfg).map_err(|e| Error::io(&nincfg_path, e))?;
    log::info!(
        "wrote {} — copy it to your SD card root for Nintendont",
        nincfg_path.display()
    );

    Ok(Summary {
        title_id: ids.title_id,
        game_id,
        title,
        package,
        out: config.out.clone(),
    })
}

fn resolve_title(config: &Config, game_id: &str) -> String {
    if let Some(t) = &config.title {
        return t.clone();
    }
    if config.online {
        if let Ok(Some(name)) = gametdb::lookup_title(game_id) {
            return name;
        }
    }
    game_id.to_string()
}

/// Choose the GamePad (DRC) boot PNG: its own art if present, otherwise fall back to the TV
/// image so both screens show a matching splash (`png_to_tga` resizes it to the DRC dimensions;
/// both are 16:9, so there is no distortion). `None` when neither is available (keep the base's).
fn drc_source(drc: Option<Vec<u8>>, tv: &Option<Vec<u8>>) -> Option<Vec<u8>> {
    drc.or_else(|| tv.clone())
}

/// Write a boot texture from a user-supplied PNG, an online download, or leave the base's.
///
/// When no GamePad-specific art is found, the TV image is reused for `bootDrcTex` so both screens
/// match (the community art repos usually only carry the TV image).
fn resolve_textures(config: &Config, platform: &str, game_id: &str, meta_dir: &Path) -> Result<()> {
    // Resolve a texture's source PNG: an override path, else an online download, else None.
    let resolve_src =
        |tex: BootTexture, override_png: &Option<PathBuf>| -> Result<Option<Vec<u8>>> {
            if let Some(path) = override_png {
                Ok(Some(std::fs::read(path).map_err(|e| Error::io(path, e))?))
            } else if config.online {
                Ok(artrepo::download_texture(platform, game_id, tex).unwrap_or(None))
            } else {
                Ok(None)
            }
        };
    let write_tex = |tex: BootTexture, bytes: &[u8]| -> Result<()> {
        let tga = png_to_tga(bytes, tex)?;
        let path = meta_dir.join(tex.filename());
        std::fs::write(&path, tga).map_err(|e| Error::io(&path, e))?;
        log::info!("wrote {}", tex.filename());
        Ok(())
    };

    if let Some(bytes) = resolve_src(BootTexture::Icon, &config.icon_png)? {
        write_tex(BootTexture::Icon, &bytes)?;
    }

    let tv = resolve_src(BootTexture::BootTv, &config.boot_tv_png)?;
    if let Some(bytes) = &tv {
        write_tex(BootTexture::BootTv, bytes)?;
    }

    let drc_own = resolve_src(BootTexture::BootDrc, &config.boot_drc_png)?;
    if drc_own.is_none() && tv.is_some() {
        log::info!("no GamePad boot art found; reusing the TV image for bootDrcTex");
    }
    if let Some(bytes) = drc_source(drc_own, &tv) {
        write_tex(BootTexture::BootDrc, &bytes)?;
    }
    Ok(())
}

/// The RSA-2048 signature region of a Wii ticket/TMD (`0x004..0x104`).
const WII_SIG: std::ops::Range<usize> = 0x004..0x104;

/// Fakesign a Wii ticket or TMD by zeroing its RSA signature. `fw.img`'s signature check is patched
/// to accept a zeroed signature, so `rvlt.tik`/`rvlt.tmd` must be fakesigned this way (their
/// original Nintendo signatures are rejected by the patched check and hang the emulator at boot).
fn fakesign(data: &mut [u8]) {
    if data.len() >= WII_SIG.end {
        data[WII_SIG].fill(0);
    }
}

/// After a `main.dol` patch or trim, point the Wii partition TMD's single content record at the
/// rebuilt H3 table and fakesign it. The Wii TMD stores the content hash at `0x1F4` and its
/// RSA-2048 signature at `0x004..0x104`.
fn update_rvlt_tmd(tmd: &mut [u8], content_hash: &[u8; 20]) {
    const CONTENT0_HASH: usize = 0x1F4;
    if tmd.len() >= CONTENT0_HASH + 20 {
        tmd[WII_SIG].fill(0);
        tmd[CONTENT0_HASH..CONTENT0_HASH + 20].copy_from_slice(content_hash);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drc_uses_own_art_when_present() {
        let drc = Some(vec![1, 2, 3]);
        let tv = Some(vec![9, 9]);
        assert_eq!(drc_source(drc, &tv), Some(vec![1, 2, 3]));
    }

    #[test]
    fn drc_falls_back_to_tv_when_absent() {
        let tv = Some(vec![9, 9]);
        assert_eq!(drc_source(None, &tv), Some(vec![9, 9]));
    }

    #[test]
    fn drc_is_none_when_neither_present() {
        assert_eq!(drc_source(None, &None), None);
    }
}
