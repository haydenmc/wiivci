//! `wiivci` — inject a Wii game into a Wii U Virtual Console (WUP) package.
//!
//! Copyright (C) 2026 Hayden. Licensed under the GNU General Public License, version 3 or
//! later. This program comes with ABSOLUTELY NO WARRANTY. See the LICENSE file for details.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, Context, Result};
use clap::{ArgGroup, Parser, ValueEnum};

use wiivci_core::base::{open_base, BaseSource};
use wiivci_core::keys::WiiUCommonKey;
use wiivci_core::nus::{NusBase, NusClient};
use wiivci_core::package::cert::CertChain;
use wiivci_core::pipeline::{self, Config, Region};

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

    /// Keep the intermediate build directory instead of deleting it.
    #[arg(long, value_name = "DIR")]
    work_dir: Option<PathBuf>,
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
