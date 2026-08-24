//! Nintendont configuration file (`nincfg.bin`).
//!
//! When a GameCube title is injected, the emitted Wii U VC disc boots **Nintendont** as its
//! `main.dol` (see [`crate::wii_author`]); Nintendont in turn reads its runtime configuration
//! from `nincfg.bin` at the SD-card root. That file is therefore **not** part of the WUP package
//! — we generate it alongside the output so the user can drop it on their SD card.
//!
//! The layout mirrors Nintendont's `NIN_CFG` struct (`common/include/CommonConfig.h`, config
//! version 10). It is a fixed 546-byte (`0x222`) record; all multi-byte integers are **big-endian**
//! (Nintendont runs on the PowerPC Wii/vWii and byteswaps against that native order). We target
//! `di:/game.iso`, i.e. the game read from the emulated disc rather than USB/SD.

/// Total size of a version-10 `NIN_CFG` record.
pub const NINCFG_SIZE: usize = 0x222;

/// Config version this generator emits (`NIN_CFG` v10, which adds `WiiUGamepadSlot`).
const NINCFG_VERSION: u32 = 0x0000_000A;
/// `NIN_CFG.Magicbytes`.
const NINCFG_MAGIC: u32 = 0x0107_0CF6;

// Field offsets within the record.
const OFF_MAGIC: usize = 0x000;
const OFF_VERSION: usize = 0x004;
const OFF_CONFIG: usize = 0x008;
const OFF_VIDEOMODE: usize = 0x00C;
const OFF_LANGUAGE: usize = 0x010;
const OFF_GAMEPATH: usize = 0x014; // char[255]
const OFF_CHEATPATH: usize = 0x113; // char[255]
const OFF_MAXPADS: usize = 0x212;
const OFF_GAMEID: usize = 0x216; // 4 ASCII bytes
const OFF_MEMCARDBLOCKS: usize = 0x21A;
const OFF_VIDEOSCALE: usize = 0x21B;
const OFF_VIDEOOFFSET: usize = 0x21C;
const OFF_NETWORKPROFILE: usize = 0x21D;
const OFF_WIIU_GAMEPAD_SLOT: usize = 0x21E;

const PATH_LEN: usize = 255;

// `NIN_CFG.Config` bit flags (subset we use; see Nintendont `CommonConfig.h`).
const CFG_CHEATS: u32 = 0x0000_0001;
const CFG_MEMCARDEMU: u32 = 0x0000_0008;
const CFG_CHEAT_PATH: u32 = 0x0000_0010;
const CFG_FORCE_WIDE: u32 = 0x0000_0020;
const CFG_AUTO_BOOT: u32 = 0x0000_0080;
const CFG_WIIU_WIDE: u32 = 0x0000_8000;

// `NIN_CFG.VideoMode` values.
const VID_AUTO: u32 = 0x0000_0000;
const VID_FORCE: u32 = 0x0001_0000;
const VID_NONE: u32 = 0x0002_0000;
const VID_PAL50: u32 = 0x0000_0001;
const VID_PAL60: u32 = 0x0000_0002;
const VID_NTSC: u32 = 0x0000_0004;
const VID_MPAL: u32 = 0x0000_0008;
const VID_PROG: u32 = 0x0000_0010;

/// GameCube language selection (`NIN_CFG.Language`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Language {
    /// Let Nintendont pick per the console/game (`-1`).
    #[default]
    Auto,
    /// English.
    English,
    /// German.
    German,
    /// French.
    French,
    /// Spanish.
    Spanish,
    /// Italian.
    Italian,
    /// Dutch.
    Dutch,
}

impl Language {
    fn value(self) -> u32 {
        match self {
            Language::Auto => 0xFFFF_FFFF, // -1
            Language::English => 0,
            Language::German => 1,
            Language::French => 2,
            Language::Spanish => 3,
            Language::Italian => 4,
            Language::Dutch => 5,
        }
    }
}

/// Forced video mode (`NIN_CFG.VideoMode`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VideoMode {
    /// Match the game's native mode (default).
    #[default]
    Auto,
    /// Force NTSC 480i.
    ForceNtsc,
    /// Force PAL50.
    ForcePal50,
    /// Force PAL60.
    ForcePal60,
    /// Force MPAL.
    ForceMpal,
    /// Force progressive (480p); combined with the region's mode.
    ForceProgressive,
    /// Disable Nintendont's video handling entirely.
    None,
}

impl VideoMode {
    fn value(self) -> u32 {
        match self {
            VideoMode::Auto => VID_AUTO,
            VideoMode::ForceNtsc => VID_FORCE | VID_NTSC,
            VideoMode::ForcePal50 => VID_FORCE | VID_PAL50,
            VideoMode::ForcePal60 => VID_FORCE | VID_PAL60,
            VideoMode::ForceMpal => VID_FORCE | VID_MPAL,
            VideoMode::ForceProgressive => VID_FORCE | VID_NTSC | VID_PROG,
            VideoMode::None => VID_NONE,
        }
    }
}

/// Options controlling the generated `nincfg.bin`.
#[derive(Clone, Debug)]
pub struct NincfgOptions {
    /// The GameCube game id (4 ASCII bytes, e.g. `GALE`).
    pub game_id: [u8; 4],
    /// Force a 16:9 aspect ratio (sets both `FORCE_WIDE` and the Wii U-specific `WIIU_WIDE`).
    pub widescreen: bool,
    /// GameCube language.
    pub language: Language,
    /// Forced video mode.
    pub video_mode: VideoMode,
    /// Emulate a memory card (a `.raw` file Nintendont creates on SD).
    pub memcard_emu: bool,
    /// Memory-card size exponent `x` in `0..=4` (blocks = `(1 << (x + 6)) - 5`); `2` ⇒ 251 blocks
    /// (the standard 512 KiB card). Only meaningful when `memcard_emu` is set.
    pub memcard_blocks: u8,
    /// Path to a Gecko cheat file on SD (`sd:/…/game.gct`); enables cheats when `Some`.
    pub cheat_path: Option<String>,
    /// Maximum controllers (`0..=4`).
    pub max_pads: u32,
    /// Which Wii U GamePad maps to a controller slot (v10 field).
    pub wiiu_gamepad_slot: u32,
}

impl Default for NincfgOptions {
    fn default() -> Self {
        NincfgOptions {
            game_id: *b"____",
            widescreen: false,
            language: Language::Auto,
            video_mode: VideoMode::Auto,
            memcard_emu: true,
            memcard_blocks: 2,
            cheat_path: None,
            max_pads: 4,
            wiiu_gamepad_slot: 0,
        }
    }
}

/// The disc path Nintendont reads the game from on a Wii U VC inject (the emulated disc).
const GAME_PATH: &str = "di:/game.iso";

/// Serialize `opts` into a 546-byte `nincfg.bin` record.
pub fn generate(opts: &NincfgOptions) -> [u8; NINCFG_SIZE] {
    let mut buf = [0u8; NINCFG_SIZE];

    let mut config = CFG_AUTO_BOOT;
    if opts.memcard_emu {
        config |= CFG_MEMCARDEMU;
    }
    if opts.widescreen {
        config |= CFG_FORCE_WIDE | CFG_WIIU_WIDE;
    }
    if opts.cheat_path.is_some() {
        config |= CFG_CHEATS | CFG_CHEAT_PATH;
    }

    put_u32(&mut buf, OFF_MAGIC, NINCFG_MAGIC);
    put_u32(&mut buf, OFF_VERSION, NINCFG_VERSION);
    put_u32(&mut buf, OFF_CONFIG, config);
    put_u32(&mut buf, OFF_VIDEOMODE, opts.video_mode.value());
    put_u32(&mut buf, OFF_LANGUAGE, opts.language.value());
    put_cstr(&mut buf, OFF_GAMEPATH, PATH_LEN, GAME_PATH);
    if let Some(path) = &opts.cheat_path {
        put_cstr(&mut buf, OFF_CHEATPATH, PATH_LEN, path);
    }
    put_u32(&mut buf, OFF_MAXPADS, opts.max_pads);
    // GameID is 4 ASCII bytes stored in reading order (equivalent to a big-endian u32).
    buf[OFF_GAMEID..OFF_GAMEID + 4].copy_from_slice(&opts.game_id);
    buf[OFF_MEMCARDBLOCKS] = opts.memcard_blocks;
    buf[OFF_VIDEOSCALE] = 0; // s8, centered
    buf[OFF_VIDEOOFFSET] = 0; // s8, centered
    buf[OFF_NETWORKPROFILE] = 0;
    put_u32(&mut buf, OFF_WIIU_GAMEPAD_SLOT, opts.wiiu_gamepad_slot);

    buf
}

fn put_u32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_be_bytes());
}

/// Write a NUL-terminated ASCII string into a fixed `len`-byte field, truncating to leave room
/// for the terminator. The field is already zeroed, so a short string is NUL-padded.
fn put_cstr(buf: &mut [u8], off: usize, len: usize, s: &str) {
    let max = len - 1;
    let bytes = s.as_bytes();
    let n = bytes.len().min(max);
    buf[off..off + n].copy_from_slice(&bytes[..n]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u32(buf: &[u8], off: usize) -> u32 {
        u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }

    #[test]
    fn record_is_exactly_546_bytes() {
        assert_eq!(NINCFG_SIZE, 546);
        let cfg = generate(&NincfgOptions::default());
        assert_eq!(cfg.len(), 546);
    }

    #[test]
    fn magic_version_and_gamepath_are_written_big_endian() {
        let cfg = generate(&NincfgOptions {
            game_id: *b"GALE",
            ..Default::default()
        });
        assert_eq!(read_u32(&cfg, OFF_MAGIC), 0x0107_0CF6);
        assert_eq!(read_u32(&cfg, OFF_VERSION), 10);
        // Big-endian byte order on disc.
        assert_eq!(&cfg[OFF_MAGIC..OFF_MAGIC + 4], &[0x01, 0x07, 0x0C, 0xF6]);

        // GamePath is NUL-terminated ASCII "di:/game.iso".
        let end = cfg[OFF_GAMEPATH..OFF_GAMEPATH + PATH_LEN]
            .iter()
            .position(|&b| b == 0)
            .unwrap();
        assert_eq!(&cfg[OFF_GAMEPATH..OFF_GAMEPATH + end], b"di:/game.iso");
        assert_eq!(cfg[OFF_GAMEPATH + end], 0);

        // GameID stored as the 4 ASCII chars in order.
        assert_eq!(&cfg[OFF_GAMEID..OFF_GAMEID + 4], b"GALE");
    }

    #[test]
    fn default_config_autoboots_with_memcard_emulation() {
        let cfg = generate(&NincfgOptions::default());
        let config = read_u32(&cfg, OFF_CONFIG);
        assert_eq!(config & CFG_AUTO_BOOT, CFG_AUTO_BOOT, "should autoboot");
        assert_eq!(
            config & CFG_MEMCARDEMU,
            CFG_MEMCARDEMU,
            "memcard emu default"
        );
        assert_eq!(config & CFG_FORCE_WIDE, 0, "not widescreen by default");
        assert_eq!(config & CFG_CHEATS, 0, "no cheats by default");
    }

    #[test]
    fn widescreen_sets_both_force_wide_and_wiiu_wide() {
        let cfg = generate(&NincfgOptions {
            widescreen: true,
            ..Default::default()
        });
        let config = read_u32(&cfg, OFF_CONFIG);
        assert_eq!(config & CFG_FORCE_WIDE, CFG_FORCE_WIDE);
        assert_eq!(config & CFG_WIIU_WIDE, CFG_WIIU_WIDE);
    }

    #[test]
    fn cheat_path_enables_cheats_and_is_written() {
        let cfg = generate(&NincfgOptions {
            cheat_path: Some("sd:/codes/GALE01.gct".into()),
            ..Default::default()
        });
        let config = read_u32(&cfg, OFF_CONFIG);
        assert_eq!(config & CFG_CHEATS, CFG_CHEATS);
        assert_eq!(config & CFG_CHEAT_PATH, CFG_CHEAT_PATH);
        let end = cfg[OFF_CHEATPATH..OFF_CHEATPATH + PATH_LEN]
            .iter()
            .position(|&b| b == 0)
            .unwrap();
        assert_eq!(
            &cfg[OFF_CHEATPATH..OFF_CHEATPATH + end],
            b"sd:/codes/GALE01.gct"
        );
    }

    #[test]
    fn language_auto_is_negative_one() {
        let cfg = generate(&NincfgOptions {
            language: Language::Auto,
            ..Default::default()
        });
        assert_eq!(read_u32(&cfg, OFF_LANGUAGE), 0xFFFF_FFFF);

        let cfg = generate(&NincfgOptions {
            language: Language::French,
            ..Default::default()
        });
        assert_eq!(read_u32(&cfg, OFF_LANGUAGE), 2);
    }

    #[test]
    fn video_mode_auto_is_zero_and_progressive_sets_prog_bit() {
        let cfg = generate(&NincfgOptions::default());
        assert_eq!(read_u32(&cfg, OFF_VIDEOMODE), 0);

        let cfg = generate(&NincfgOptions {
            video_mode: VideoMode::ForceProgressive,
            ..Default::default()
        });
        let v = read_u32(&cfg, OFF_VIDEOMODE);
        assert_eq!(v & VID_FORCE, VID_FORCE);
        assert_eq!(v & VID_PROG, VID_PROG);
    }

    #[test]
    fn scalar_tail_fields_land_at_their_offsets() {
        let cfg = generate(&NincfgOptions {
            memcard_blocks: 3,
            max_pads: 4,
            wiiu_gamepad_slot: 1,
            ..Default::default()
        });
        assert_eq!(read_u32(&cfg, OFF_MAXPADS), 4);
        assert_eq!(cfg[OFF_MEMCARDBLOCKS], 3);
        assert_eq!(read_u32(&cfg, OFF_WIIU_GAMEPAD_SLOT), 1);
        // The record ends immediately after WiiUGamepadSlot.
        assert_eq!(OFF_WIIU_GAMEPAD_SLOT + 4, NINCFG_SIZE);
    }
}
