//! Error type shared across the core library.

use std::path::PathBuf;

/// Result alias using the crate [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Errors produced by the injection pipeline.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A required key had the wrong length or failed hash validation.
    #[error("invalid {name} key: {reason}")]
    InvalidKey {
        /// Which key (e.g. "Wii common", "Wii U common").
        name: &'static str,
        /// Why it was rejected.
        reason: String,
    },

    /// A required file was missing from disk (e.g. a base-title component).
    #[error("missing required file: {0}")]
    MissingFile(PathBuf),

    /// The source disc image was not a supported Wii disc.
    #[error("unsupported or invalid source disc: {0}")]
    UnsupportedDisc(String),

    /// A limit imposed by an on-disk format was exceeded.
    #[error("format limit exceeded: {0}")]
    FormatLimit(String),

    /// Error bubbled up from the `nod` disc-image library.
    #[error("disc image error: {0}")]
    Nod(#[from] nod::Error),

    /// Underlying I/O error, annotated with the path it occurred on.
    #[error("I/O error on {path}: {source}")]
    Io {
        /// Path the I/O was performed against.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },

    /// Any other error.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// Wrap a [`std::io::Error`] with the path it happened on.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}
