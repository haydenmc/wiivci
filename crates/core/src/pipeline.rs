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
use crate::input::SourceDisc;
use crate::keys::WiiUCommonKey;
use crate::meta::appxml;
use crate::meta::metaxml::{patch as patch_meta, MetaOptions};
use crate::meta::titleid;
use crate::nfs::build_nfs;
use crate::package::cert::CertChain;
use crate::package::{build_package, PackageParams, PackageStats};
use crate::video::VideoPatches;

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
    /// Optional `main.dol` video patches (flicker filter / dithering).
    pub video: VideoPatches,
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
    let plan = disc_patch::plan_disc(&mut source, &config.video)?;

    // 3. Convert the disc to NFS under content/, rebuilding the Wii hash tree.
    log::info!("building NFS (this reads the whole disc)…");
    let nfs_stats = build_nfs(&mut source, &staged.htk, &staged.content_dir, &plan)?;
    log::info!(
        "NFS: {} file(s), {} bytes",
        nfs_stats.file_count,
        nfs_stats.total_bytes
    );

    // 4. Game ticket/TMD become rvlt.tik / rvlt.tmd. When the disc was patched, rvlt.tmd's
    //    content hash must be updated to the rebuilt H3 table and re-fakesigned.
    std::fs::write(staged.code_dir.join("rvlt.tik"), source.raw_ticket())
        .map_err(|e| Error::io(staged.code_dir.join("rvlt.tik"), e))?;
    let mut rvlt_tmd = source.raw_tmd().to_vec();
    if let Some(content_hash) = plan.rvlt_content_hash {
        update_rvlt_tmd(&mut rvlt_tmd, &content_hash);
    }
    std::fs::write(staged.code_dir.join("rvlt.tmd"), &rvlt_tmd)
        .map_err(|e| Error::io(staged.code_dir.join("rvlt.tmd"), e))?;

    // 5. Fakesign-patch fw.img so the (fakesigned) title is accepted.
    patch_fwimg_fakesign(&staged.code_dir.join("fw.img"))?;

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
    resolve_textures(&config, &game_id, &staged.meta_dir)?;

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

/// Write a boot texture from a user-supplied PNG, an online download, or leave the base's.
fn resolve_textures(config: &Config, game_id: &str, meta_dir: &Path) -> Result<()> {
    let jobs = [
        (BootTexture::Icon, &config.icon_png),
        (BootTexture::BootTv, &config.boot_tv_png),
        (BootTexture::BootDrc, &config.boot_drc_png),
    ];
    for (tex, override_png) in jobs {
        let png_bytes = if let Some(path) = override_png {
            Some(std::fs::read(path).map_err(|e| Error::io(path, e))?)
        } else if config.online {
            artrepo::download_texture("wii", game_id, tex).unwrap_or(None)
        } else {
            None
        };
        if let Some(bytes) = png_bytes {
            let tga = png_to_tga(&bytes, tex)?;
            let path = meta_dir.join(tex.filename());
            std::fs::write(&path, tga).map_err(|e| Error::io(&path, e))?;
            log::info!("wrote {}", tex.filename());
        }
    }
    Ok(())
}

/// After a `main.dol` patch, point the Wii partition TMD's single content record at the rebuilt
/// H3 table and fakesign it. The Wii TMD stores the content hash at `0x1F4` and its RSA-2048
/// signature at `0x004..0x104`; zeroing the signature is accepted on signature-patched consoles
/// (the same basis this tool already relies on for `title.tmd`/`title.tik`).
fn update_rvlt_tmd(tmd: &mut [u8], content_hash: &[u8; 20]) {
    const SIG: std::ops::Range<usize> = 0x004..0x104;
    const CONTENT0_HASH: usize = 0x1F4;
    if tmd.len() >= CONTENT0_HASH + 20 {
        tmd[SIG].fill(0);
        tmd[CONTENT0_HASH..CONTENT0_HASH + 20].copy_from_slice(content_hash);
    }
}

/// Neuter `fw.img`'s signature check by zeroing the byte after the `20 07 23 A2` pattern, so
/// the fakesigned title is accepted (the console still needs signature patches at runtime).
fn patch_fwimg_fakesign(path: &Path) -> Result<()> {
    let mut data = std::fs::read(path).map_err(|e| Error::io(path, e))?;
    const PATTERN: [u8; 4] = [0x20, 0x07, 0x23, 0xA2];
    let mut patched = 0;
    let mut i = 0;
    while i + PATTERN.len() <= data.len() {
        if data[i..i + 4] == PATTERN {
            data[i + 1] = 0x00;
            patched += 1;
            i += 4;
        } else {
            i += 1;
        }
    }
    if patched > 0 {
        std::fs::write(path, &data).map_err(|e| Error::io(path, e))?;
        log::info!("patched fw.img fakesigning ({patched} site(s))");
    } else {
        log::warn!("fw.img fakesign pattern not found; title may not load without it");
    }
    Ok(())
}
