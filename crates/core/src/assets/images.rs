//! Conversion of PNG artwork into the raw, uncompressed TGA textures the Wii U menu expects.
//!
//! The console loads four fixed-size textures per title. Each is a truecolor,
//! bottom-up TGA 2.0 file with no compression; we hand-write the format rather than use
//! `image`'s TGA encoder so the origin, channel order and footer match exactly.

use image::imageops::FilterType;

use crate::error::{Error, Result};

/// TGA 2.0 footer signature required by the format.
const TGA_FOOTER_SIGNATURE: &[u8; 18] = b"TRUEVISION-XFILE.\0";

/// One of the four boot/menu textures a Wii U title carries in `meta/`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootTexture {
    /// The 128x128 title icon shown in the Wii U menu.
    Icon,
    /// The 1280x720 TV boot splash.
    BootTv,
    /// The 854x480 GamePad boot splash.
    BootDrc,
    /// The 170x42 logo shown during boot.
    BootLogo,
}

impl BootTexture {
    /// Pixel dimensions `(width, height)` the console expects for this texture.
    pub fn dims(self) -> (u32, u32) {
        match self {
            BootTexture::Icon => (128, 128),
            BootTexture::BootTv => (1280, 720),
            BootTexture::BootDrc => (854, 480),
            BootTexture::BootLogo => (170, 42),
        }
    }

    /// Bits per pixel: 32 (BGRA) for textures with alpha, 24 (BGR) otherwise.
    pub fn bpp(self) -> u8 {
        match self {
            BootTexture::Icon | BootTexture::BootLogo => 32,
            BootTexture::BootTv | BootTexture::BootDrc => 24,
        }
    }

    /// The `meta/` filename this texture is stored under.
    pub fn filename(self) -> &'static str {
        match self {
            BootTexture::Icon => "iconTex.tga",
            BootTexture::BootTv => "bootTvTex.tga",
            BootTexture::BootDrc => "bootDrcTex.tga",
            BootTexture::BootLogo => "bootLogoTex.tga",
        }
    }
}

/// Decode `png_bytes`, resize it to exactly `tex`'s dimensions, and hand-encode it as an
/// uncompressed, bottom-up TGA in the pixel format the console expects (BGR for 24bpp
/// textures, BGRA for 32bpp textures).
pub fn png_to_tga(png_bytes: &[u8], tex: BootTexture) -> Result<Vec<u8>> {
    let img = image::load_from_memory(png_bytes)
        .map_err(|e| Error::Other(anyhow::anyhow!("failed to decode PNG: {e}")))?;

    let (width, height) = tex.dims();
    let resized = img.resize_exact(width, height, FilterType::Lanczos3);
    let rgba = resized.to_rgba8();

    let bpp = tex.bpp();
    let bytes_per_pixel = (bpp / 8) as usize;
    let mut pixels = Vec::with_capacity(width as usize * height as usize * bytes_per_pixel);

    // TGA pixel data is bottom-up: emit rows from the last image row to the first.
    for y in (0..height).rev() {
        for x in 0..width {
            let p = rgba.get_pixel(x, y).0;
            pixels.push(p[2]); // B
            pixels.push(p[1]); // G
            pixels.push(p[0]); // R
            if bytes_per_pixel == 4 {
                pixels.push(p[3]); // A
            }
        }
    }

    let mut out = Vec::with_capacity(18 + pixels.len() + 26);
    out.push(0); // id length
    out.push(0); // color map type
    out.push(2); // image type: uncompressed truecolor
    out.extend_from_slice(&[0u8; 5]); // color map spec
    out.extend_from_slice(&0u16.to_le_bytes()); // x origin
    out.extend_from_slice(&0u16.to_le_bytes()); // y origin
    out.extend_from_slice(&(width as u16).to_le_bytes());
    out.extend_from_slice(&(height as u16).to_le_bytes());
    out.push(bpp);
    out.push(if bpp == 32 { 0x08 } else { 0x00 }); // image descriptor: alpha bits / origin
    out.extend_from_slice(&pixels);
    out.extend_from_slice(&0u32.to_le_bytes()); // extension area offset
    out.extend_from_slice(&0u32.to_le_bytes()); // developer directory offset
    out.extend_from_slice(TGA_FOOTER_SIGNATURE);

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};
    use std::io::Cursor;

    fn solid_red_png() -> Vec<u8> {
        let img: ImageBuffer<Rgba<u8>, Vec<u8>> =
            ImageBuffer::from_pixel(4, 4, Rgba([255, 0, 0, 255]));
        let mut bytes = Vec::new();
        img.write_to(&mut Cursor::new(&mut bytes), image::ImageFormat::Png)
            .expect("encode png");
        bytes
    }

    fn assert_header(data: &[u8], tex: BootTexture) {
        let (w, h) = tex.dims();
        let bpp = tex.bpp();
        assert_eq!(data[0], 0, "id length");
        assert_eq!(data[1], 0, "color map type");
        assert_eq!(data[2], 2, "image type");
        assert_eq!(&data[3..8], &[0u8; 5], "color map spec");
        assert_eq!(u16::from_le_bytes([data[8], data[9]]), 0, "x origin");
        assert_eq!(u16::from_le_bytes([data[10], data[11]]), 0, "y origin");
        assert_eq!(u16::from_le_bytes([data[12], data[13]]), w as u16, "width");
        assert_eq!(u16::from_le_bytes([data[14], data[15]]), h as u16, "height");
        assert_eq!(data[16], bpp, "bpp");
        let expected_desc = if bpp == 32 { 0x08 } else { 0x00 };
        assert_eq!(data[17], expected_desc, "image descriptor");

        let expected_len = 18 + (w as usize * h as usize * (bpp as usize / 8)) + 26;
        assert_eq!(data.len(), expected_len, "total length");

        let footer = &data[data.len() - 18..];
        assert_eq!(footer, TGA_FOOTER_SIGNATURE, "footer signature");
    }

    #[test]
    fn icon_texture_matches_format() {
        let png = solid_red_png();
        let tga = png_to_tga(&png, BootTexture::Icon).expect("convert");
        assert_header(&tga, BootTexture::Icon);
        // Solid red -> BGRA = 00 00 FF FF for every pixel, including the first.
        assert_eq!(&tga[18..22], &[0x00, 0x00, 0xFF, 0xFF]);
    }

    #[test]
    fn boot_tv_texture_matches_format() {
        let png = solid_red_png();
        let tga = png_to_tga(&png, BootTexture::BootTv).expect("convert");
        assert_header(&tga, BootTexture::BootTv);
        assert_eq!(&tga[18..21], &[0x00, 0x00, 0xFF]);
    }

    #[test]
    fn boot_drc_texture_matches_format() {
        let png = solid_red_png();
        let tga = png_to_tga(&png, BootTexture::BootDrc).expect("convert");
        assert_header(&tga, BootTexture::BootDrc);
        assert_eq!(&tga[18..21], &[0x00, 0x00, 0xFF]);
    }

    #[test]
    fn boot_logo_texture_matches_format() {
        let png = solid_red_png();
        let tga = png_to_tga(&png, BootTexture::BootLogo).expect("convert");
        assert_header(&tga, BootTexture::BootLogo);
        assert_eq!(&tga[18..22], &[0x00, 0x00, 0xFF, 0xFF]);
    }

    #[test]
    fn filenames_match_console_expectations() {
        assert_eq!(BootTexture::Icon.filename(), "iconTex.tga");
        assert_eq!(BootTexture::BootTv.filename(), "bootTvTex.tga");
        assert_eq!(BootTexture::BootDrc.filename(), "bootDrcTex.tga");
        assert_eq!(BootTexture::BootLogo.filename(), "bootLogoTex.tga");
    }
}
