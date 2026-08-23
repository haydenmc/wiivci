# wiivci

A cross-platform CLI that injects Wii games (ISO/RVZ/WBFS/…) into Wii U Virtual Console
titles — producing an installable WUP package you can sideload with
[WUP Installer GX2](https://github.com/FIX94/wup-installer-gx2). It fills the same role as
TeconmoonWiiVCInjector and UWUVCI, but is a single self-contained Rust binary with **no hard
dependency on external tools** (`wit`, `nfs2iso2nfs`, `NUSPacker`, `CDecrypt`, `png2tgacmd`,
…). Optional network calls are used only to look up a title string and cover art.

> **Status:** the entire WUP format pipeline is implemented and validated byte-for-byte
> against a retail title (see [Validation](#validation)). Final confirmation of a booting
> title still requires installing on real hardware.

## What you provide

Like every injector, this tool never bundles copyrighted or secret material. You supply:

| Input | Flag | Notes |
|-------|------|-------|
| A Wii disc image | `--input` | ISO, RVZ, WBFS, CISO, NKit, GCZ — read via [`nod`](https://github.com/encounter/nod). |
| A Wii U VC **base title** | `--base` *or* `--base-title-id` | A Cemu `.wua` archive / extracted directory (`--base`), **or** downloaded live from NUS (`--base-title-id <16-hex>` + `--base-title-key`). By convention Rhythm Heaven Fever (`00050000101B0700`). Supplies the closed Nintendo framework (`fw.img`, `frisbiiU.rpx`, …) that has no clean-room reimplementation. |
| The **Wii U common key** | `--wiiu-common-key` | 32 hex chars, a key file, or the `WIIU_COMMON_KEY` env var. Validated by fingerprint. Used to encrypt the title key into the ticket. |
| A **certificate chain** | `--cert` | `title.cert` from any dumped Wii U title. It is Nintendo's public chain, required by the format, and identical across titles — so it is user-supplied rather than bundled. |

The **Wii common key** is *not* required: `nod` decrypts Wii disc partitions internally.

## Usage

```sh
wiivci \
  --input "Wii Sports (USA).rvz" \
  --base  "Rhythm Heaven Fever [00050000101B0700].wua" \
  --out   ./out \
  --wiiu-common-key <32-hex> \
  --cert  ./title.cert \
  --title "Wii Sports"
```

Then copy `./out` to `sd:/install/<name>/` and install with WUP Installer GX2. The target
console needs signature patches (Aroma/Tiramisu/Mocha) to install and boot fakesigned titles.

Useful options: `--icon/--boot-tv/--boot-drc <png>` to supply artwork, `--region jp|us|eu`,
`--no-gamepad`, `--offline` (skip GameTDB/art lookups), `--work-dir <dir>` (keep the
intermediate build tree).

### Video patches

Optional patches to the game's `main.dol` (the same ones UWUVCI offers), for a sharper picture:

* `--deflicker` — remove the vertical flicker filter entirely.
* `--half-vfilter` — halve the vertical filter instead of removing it (softer).
* `--remove-dithering` — remove framebuffer dithering (better colour accuracy).

These edit the game executable inside the disc, so the tool relocates `main.dol`, applies the
patch, and rebuilds the Wii partition hash tree over the affected clusters (updating the H3
table and re-fakesigning `rvlt.tmd`). A requested patch whose signature isn't present in a given
game is skipped with a warning.

### Downloading the base from NUS

Instead of `--base`, you can have the tool fetch the base title straight from Nintendo's CCS
CDN and decrypt it in-process (a CDecrypt-style extractor). You provide the title id and its
encrypted title key (as found in title-key databases — NUS does not serve tickets for paid
titles):

```sh
wiivci \
  --input "Wii Sports (USA).rvz" \
  --base-title-id  00050000101B0700 \
  --base-title-key <32-hex encrypted title key> \
  --out ./out --wiiu-common-key <32-hex> --cert ./title.cert --title "Wii Sports"
```

Only the contents needed for the base framework are downloaded — the base's own game data
(`hif_*.nfs`, ~450 MB) is skipped since the injected game replaces it. `--base-version <n>`
pins a TMD version and `--nus-url <url>` points at a mirror.

## How it works

1. **Read** the source disc with `nod` (decrypts Wii partitions, handles RVZ/WBFS/…).
2. **Stage** the base title's `code/`/`content/`/`meta/` into a build directory (`.wua` read
   natively via the pure-Rust [`zarust`](https://crates.io/crates/zarust)).
3. **NFS**: pack the decrypted disc into `hif_%06d.nfs` (EGGS header + sparse LBA table +
   per-sector AES-128-CBC with the base's `htk.bin`, split at 250 MiB). The Wii partition hash
   tree (H0–H3) is rebuilt while packing — required because RVZ/WIA sources store the data with
   the per-cluster hash blocks zeroed — and any `main.dol` video patches are applied here.
4. Drop in the game's `rvlt.tik`/`rvlt.tmd` and fakesign-patch `fw.img`.
5. **Metadata**: regenerate `code/app.xml` and patch `meta/meta.xml` (title id, names,
   region); render `meta/*.tga` boot textures from PNG art.
6. **Package**: assign files to contents, build the FST, encrypt each content (with the
   H0–H3 hash tree for hashed contents), and emit `title.tmd`/`title.tik`/`title.cert` +
   `.app`/`.h3`.

## Building

Requires a Rust toolchain (1.85+) and a C compiler (for `nod`'s compression backends).

```sh
cargo build --release   # binary at target/release/wiivci
cargo test              # fast unit/format tests
```

The dev container (`.devcontainer/`) provides the toolchain automatically.

## Validation

Correctness is anchored on a retail title used as ground truth (not committed):

* the **NFS** encoder round-trips through `nod`'s NFS reader to a byte-identical decrypted
  disc;
* the **FST**, **TMD** and **ticket** serializers reproduce a retail title's bytes exactly;
* **content encryption** (non-hashed and the hashed H0–H3 tree) reproduces retail `.app`/
  `.h3` files byte-for-byte;
* built packages are re-verified end-to-end: every content decrypts and matches its TMD hash.

Cross-validation tests are `#[ignore]`d and require local reference files plus
`WIIU_COMMON_KEY`; the everyday `cargo test` run needs neither.

## Scope

v1 targets Wii ISO/RVZ → WUP with core options and the `main.dol` video patches above. Not yet
implemented: `fw.img` controller-remap patches, video-mode/region disc patches, the
GameCube/Nintendont path, and cheats.

## License

Licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later). See
[`LICENSE`](LICENSE). This is compatible with the tool's Apache-2.0/MIT-licensed dependencies
(e.g. `nod`), which GPLv3 may incorporate.

## Legal

This tool creates no copyrighted content and bundles no keys, certificates, or Nintendo
binaries. You must provide your own legally-obtained game dump, base title, common key, and
certificate chain. Reference tools were consulted only for file-format facts.
