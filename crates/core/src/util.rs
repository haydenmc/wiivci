//! Small numeric helpers shared across otherwise-unrelated modules.

/// Types [`align_up`] supports: every call site used `n.div_ceil(to) * to` before consolidation
/// (`usize` for in-memory offsets/buffer sizes, `u64` for on-disk byte sizes); this trait lets
/// [`align_up`] stay a single generic function while keeping each type's arithmetic identical to
/// before.
pub(crate) trait AlignInt: Copy + std::ops::Mul<Output = Self> {
    fn div_ceil_(self, rhs: Self) -> Self;
}

impl AlignInt for usize {
    #[inline]
    fn div_ceil_(self, rhs: Self) -> Self {
        self.div_ceil(rhs)
    }
}

impl AlignInt for u64 {
    #[inline]
    fn div_ceil_(self, rhs: Self) -> Self {
        self.div_ceil(rhs)
    }
}

/// Round `n` up to the next multiple of `to` (`n.div_ceil(to) * to`).
///
/// Previously duplicated (under the names `align_up`/`round_up`) in `wii_author.rs`,
/// `package/content.rs` and `package/content_crypto.rs`.
#[inline]
pub(crate) fn align_up<T: AlignInt>(n: T, to: T) -> T {
    n.div_ceil_(to) * to
}
