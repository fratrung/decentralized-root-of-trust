//! Where the benchmark binaries keep durable signer state.
//!
//! An XMSS member burns its slot with one journal write and one `sync_data`
//! before every signature, inside the timed region. What that costs depends on
//! the storage under the state file far more than on the scheme: nothing to
//! speak of on a RAM-backed filesystem, a device flush on a local disk, a round
//! trip on network storage. The directory is therefore a declared parameter of
//! a signing measurement, not an accident of `TMPDIR`: `benchmark.sh` sets
//! `DROT_SIGNER_STATE_DIR`, records the filesystem behind it and classifies the
//! campaign (`tools/storage_class.sh`).

use std::ffi::OsString;
use std::path::PathBuf;

/// The environment variable naming the state directory.
pub const SIGNER_STATE_DIR_ENV: &str = "DROT_SIGNER_STATE_DIR";

fn resolve(configured: Option<OsString>) -> PathBuf {
    match configured {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => std::env::temp_dir(),
    }
}

/// The directory signer state goes in: `DROT_SIGNER_STATE_DIR` when set and
/// non-empty, the system temporary directory otherwise.
pub fn signer_state_dir() -> PathBuf {
    resolve(std::env::var_os(SIGNER_STATE_DIR_ENV))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_directory_wins_and_an_empty_one_does_not() {
        assert_eq!(
            resolve(Some(OsString::from("/var/lib/member"))),
            PathBuf::from("/var/lib/member")
        );
        assert_eq!(resolve(Some(OsString::new())), std::env::temp_dir());
        assert_eq!(resolve(None), std::env::temp_dir());
    }
}
