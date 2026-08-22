//! Derivation of Wii U Virtual Console identifiers from a Wii disc's 4-byte game ID.

/// The Wii U Virtual Console title-id/group-id/product-code set derived from a Wii
/// disc's 4-byte game ID (e.g. `b"RSPE"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TitleIds {
    /// Full 64-bit Wii U title ID: `0x0005000200000000 | disc_id4_as_u32`.
    pub title_id: u64,
    /// The 4-byte disc ID interpreted as a big-endian `u32`.
    pub group_id: u32,
    /// The Wii U `meta.xml` `reserved_flag2` value, equal to `group_id`.
    pub reserved_flag2: u32,
    /// WUP product code, e.g. `"WUP-N-RSPE"`.
    pub product_code: String,
}

/// Derive the Wii U [`TitleIds`] for a Wii disc from its 4-byte game ID (e.g. `b"RSPE"`).
pub fn derive(disc_id4: [u8; 4]) -> TitleIds {
    let disc4hex = u32::from_be_bytes(disc_id4);
    let title_id = 0x0005_0002_0000_0000u64 | disc4hex as u64;
    let product_code = format!("WUP-N-{}", String::from_utf8_lossy(&disc_id4));

    TitleIds {
        title_id,
        group_id: disc4hex,
        reserved_flag2: disc4hex,
        product_code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_from_rspe() {
        let ids = derive(*b"RSPE");
        assert_eq!(ids.title_id, 0x0005000252535045);
        assert_eq!(ids.group_id, 0x52535045);
        assert_eq!(ids.reserved_flag2, 0x52535045);
        assert_eq!(ids.product_code, "WUP-N-RSPE");
    }
}
