//! `wiivci` — inject a Wii game into a Wii U Virtual Console (WUP) package.
//!
//! Copyright (C) 2026 Hayden. Licensed under the GNU General Public License, version 3 or
//! later. This program comes with ABSOLUTELY NO WARRANTY. See the LICENSE file for details.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{ArgGroup, Parser, ValueEnum};

use wiivci_core::assets::nintendont;
use wiivci_core::base::{open_base, BaseSource};
use wiivci_core::input::{probe, DiscKind};
use wiivci_core::keys::WiiUCommonKey;
use wiivci_core::nincfg::{Language, VideoMode};
use wiivci_core::nus::{NusBase, NusClient};
use wiivci_core::package::cert::CertChain;
use wiivci_core::pipeline::{self, Config, GameCubeOptions, Region};
use wiivci_core::video::VideoPatches;

/// Inject a Wii game (ISO/RVZ) into an installable Wii U Virtual Console package.
#[derive(Parser, Debug)]
#[command(name = "wiivci", version, about)]
#[command(group(ArgGroup::new("base_src").required(true).args(["base", "base_title_id"])))]
struct Cli {
    /// Source Wii disc image (ISO, RVZ, WBFS, …).
    #[arg(short, long)]
    input: PathBuf,

    /// Base Wii U VC title: a Cemu `.wua` archive or an extracted title directory.
    #[arg(short, long)]
    base: Option<PathBuf>,

    /// Instead of --base, download the base from NUS: its 16-hex title id
    /// (e.g. 00050000101B0700). Requires --base-title-key.
    #[arg(long, value_name = "HEX16")]
    base_title_id: Option<String>,

    /// Encrypted title key (32 hex) for the NUS base title, as found in title-key databases.
    #[arg(long, value_name = "HEX32", requires = "base_title_id")]
    base_title_key: Option<String>,

    /// Specific base TMD version to download (default: latest).
    #[arg(long, value_name = "N", requires = "base_title_id")]
    base_version: Option<u32>,

    /// Override the NUS/CCS base URL (default: the Nintendo CCS CDN).
    #[arg(long, value_name = "URL", requires = "base_title_id")]
    nus_url: Option<String>,

    /// Output directory for the WUP package (created if absent).
    #[arg(short, long)]
    out: PathBuf,

    /// Wii U common key: 32 hex chars, or a path to a 16-byte / hex key file.
    #[arg(long, value_name = "KEY|FILE", env = "WIIU_COMMON_KEY")]
    wiiu_common_key: String,

    /// Certificate chain (`title.cert`) from any dumped Wii U title.
    #[arg(long, value_name = "FILE")]
    cert: PathBuf,

    /// Title name shown on the Wii U menu (default: looked up on GameTDB when online).
    #[arg(long)]
    title: Option<String>,

    /// Override the 128x128 icon (PNG).
    #[arg(long, value_name = "PNG")]
    icon: Option<PathBuf>,

    /// Override the 1280x720 TV boot image (PNG).
    #[arg(long, value_name = "PNG")]
    boot_tv: Option<PathBuf>,

    /// Override the 854x480 GamePad boot image (PNG).
    #[arg(long, value_name = "PNG")]
    boot_drc: Option<PathBuf>,

    /// Target region written to meta.xml.
    #[arg(long, value_enum, default_value_t = RegionArg::Us)]
    region: RegionArg,

    /// Mark the GamePad as unusable (sets drc_use = 0).
    #[arg(long)]
    no_gamepad: bool,

    /// Disable all network lookups (GameTDB title + cover art).
    #[arg(long)]
    offline: bool,

    /// Remove the video flicker filter (patches the game's main.dol for a sharper image).
    #[arg(long)]
    deflicker: bool,

    /// Halve the vertical filter instead of removing it (softer than --deflicker).
    #[arg(long)]
    half_vfilter: bool,

    /// Remove framebuffer dithering (better colour accuracy).
    #[arg(long)]
    remove_dithering: bool,

    /// Store the whole partition instead of skipping unused inter-file gaps (much larger NFS).
    #[arg(long)]
    keep_gaps: bool,

    /// Skip storing dummy/padding files whose entire content is zero (smaller NFS; off by default).
    #[arg(long)]
    trim_zeros: bool,

    /// Force GameCube (Nintendont) mode. Normally auto-detected from the input image.
    #[arg(long)]
    gamecube: bool,

    /// GameCube: Nintendont `boot.dol` to embed (default: downloaded, pinned build).
    #[arg(long, value_name = "DOL")]
    nintendont: Option<PathBuf>,

    /// GameCube: Wii `apploader.img` for the synthetic disc. Required to boot on hardware.
    #[arg(long, value_name = "IMG")]
    apploader: Option<PathBuf>,

    /// GameCube: force 16:9 widescreen (written to nincfg.bin).
    #[arg(long)]
    widescreen: bool,

    /// GameCube: game language (written to nincfg.bin).
    #[arg(long, value_enum, default_value_t = GcLangArg::Auto)]
    gc_language: GcLangArg,

    /// GameCube: disable emulated memory card.
    #[arg(long)]
    no_memcard: bool,

    /// GameCube: SD path to a Gecko cheat file (`.gct`); enables cheats in nincfg.bin.
    #[arg(long, value_name = "SDPATH")]
    cheats: Option<String>,

    /// Keep the intermediate build directory instead of deleting it.
    #[arg(long, value_name = "DIR")]
    work_dir: Option<PathBuf>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum GcLangArg {
    Auto,
    English,
    German,
    French,
    Spanish,
    Italian,
    Dutch,
}

impl From<GcLangArg> for Language {
    fn from(l: GcLangArg) -> Self {
        match l {
            GcLangArg::Auto => Language::Auto,
            GcLangArg::English => Language::English,
            GcLangArg::German => Language::German,
            GcLangArg::French => Language::French,
            GcLangArg::Spanish => Language::Spanish,
            GcLangArg::Italian => Language::Italian,
            GcLangArg::Dutch => Language::Dutch,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum RegionArg {
    Jp,
    Us,
    Eu,
}

impl From<RegionArg> for Region {
    fn from(r: RegionArg) -> Self {
        match r {
            RegionArg::Jp => Region::Japan,
            RegionArg::Us => Region::Usa,
            RegionArg::Eu => Region::Europe,
        }
    }
}

/// Parse exactly `N` hex bytes from a string (ignoring surrounding whitespace).
fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    let s = s.trim();
    if s.len() != N * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("expected {} hex characters, got {:?}", N * 2, s));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    Ok(out)
}

/// Build the base source from the CLI: a local path, or an NUS download.
fn build_base(cli: &Cli, wiiu_common_key: &WiiUCommonKey) -> Result<Box<dyn BaseSource>> {
    if let Some(path) = &cli.base {
        return open_base(path).with_context(|| format!("opening base {}", path.display()));
    }
    // NUS path (validated present by the arg group).
    let title_id_hex = cli
        .base_title_id
        .as_ref()
        .expect("arg group guarantees this");
    let title_id = u64::from_str_radix(title_id_hex.trim(), 16)
        .with_context(|| format!("invalid --base-title-id {title_id_hex:?}"))?;
    let key_hex = cli
        .base_title_key
        .as_ref()
        .ok_or_else(|| anyhow!("--base-title-key is required with --base-title-id"))?;
    let enc_title_key = parse_hex::<16>(key_hex).context("invalid --base-title-key")?;
    let client = match &cli.nus_url {
        Some(url) => NusClient::with_base_url(url),
        None => NusClient::new(),
    }?;
    Ok(Box::new(NusBase::new(
        title_id,
        enc_title_key,
        wiiu_common_key.0,
        cli.base_version,
        client,
    )))
}

/// Resolve GameCube (Nintendont) options: obtain Nintendont's `boot.dol` (a local file or a
/// pinned download) and the optional apploader, plus nincfg settings.
fn build_gc_options(cli: &Cli) -> Result<GameCubeOptions> {
    let nintendont_dol = match &cli.nintendont {
        Some(path) => std::fs::read(path)
            .with_context(|| format!("reading Nintendont dol {}", path.display()))?,
        None => {
            if cli.offline {
                return Err(anyhow!(
                    "--nintendont <boot.dol> is required with --offline (cannot download Nintendont)"
                ));
            }
            nintendont::download_boot_dol().context(
                "downloading Nintendont (supply one with --nintendont to avoid the network)",
            )?
        }
    };
    let apploader = match &cli.apploader {
        Some(path) => {
            std::fs::read(path).with_context(|| format!("reading apploader {}", path.display()))?
        }
        None => Vec::new(),
    };
    Ok(GameCubeOptions {
        nintendont_dol,
        apploader,
        widescreen: cli.widescreen,
        language: cli.gc_language.into(),
        video_mode: VideoMode::Auto,
        memcard_emu: !cli.no_memcard,
        cheat_path: cli.cheats.clone(),
    })
}

/// Load a key from either an inline hex string or a file path.
fn load_wiiu_key(arg: &str) -> Result<WiiUCommonKey> {
    let path = std::path::Path::new(arg);
    let raw = if path.is_file() {
        std::fs::read(path).with_context(|| format!("reading key file {}", path.display()))?
    } else {
        arg.as_bytes().to_vec()
    };
    WiiUCommonKey::parse(&raw).context("invalid Wii U common key")
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    let wiiu_common_key = load_wiiu_key(&cli.wiiu_common_key)?;
    let cert = CertChain::load(&cli.cert)
        .with_context(|| format!("loading certificate chain {}", cli.cert.display()))?;
    let base = build_base(&cli, &wiiu_common_key)?;

    // GameCube mode: explicit flag or auto-detected from the input image.
    let is_gamecube = cli.gamecube || matches!(probe(&cli.input), Ok(DiscKind::GameCube));
    if is_gamecube && (cli.deflicker || cli.half_vfilter || cli.remove_dithering) {
        eprintln!("note: --deflicker/--half-vfilter/--remove-dithering are Wii-only and ignored for GameCube");
    }
    let gamecube = if is_gamecube {
        Some(build_gc_options(&cli)?)
    } else {
        None
    };

    let config = Config {
        input: cli.input,
        base,
        out: cli.out,
        wiiu_common_key,
        cert,
        title: cli.title,
        icon_png: cli.icon,
        boot_tv_png: cli.boot_tv,
        boot_drc_png: cli.boot_drc,
        region: cli.region.into(),
        gamepad: !cli.no_gamepad,
        online: !cli.offline,
        video: VideoPatches {
            deflicker: cli.deflicker,
            half_vfilter: cli.half_vfilter,
            dithering: cli.remove_dithering,
        },
        skip_gaps: !cli.keep_gaps,
        trim_zeros: cli.trim_zeros,
        gamecube,
    };

    // Use a caller-provided work dir, or a temp dir cleaned up on completion.
    let (work_path, _guard) = match &cli.work_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating work dir {}", dir.display()))?;
            (dir.clone(), None)
        }
        None => {
            let tmp = tempfile::tempdir().context("creating temp work dir")?;
            (tmp.path().to_path_buf(), Some(tmp))
        }
    };

    let summary = pipeline::run(config, &work_path)?;

    println!("\nDone.");
    println!("  Game:      {} ({})", summary.title, summary.game_id);
    println!("  Title ID:  {:016X}", summary.title_id);
    println!(
        "  Package:   {} content file(s), {:.1} MiB",
        summary.package.content_count,
        summary.package.total_content_bytes as f64 / (1024.0 * 1024.0)
    );
    println!("  Output:    {}", summary.out.display());
    println!("\nInstall the output folder with WUP Installer GX2 (sd:/install/<name>/).");
    println!("The target console needs signature patches (Aroma/Tiramisu) to install and boot.");
    if is_gamecube {
        println!(
            "GameCube: also copy the generated nincfg.bin (next to the output) to your SD card root."
        );
    }
    Ok(())
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
