//! Persistent verifier identity — load or create an ML-DSA-65 keypair on disk.
//!
//! Used by `h33-replay-verify --sign`. Each verifier instance gets its own
//! long-lived identity; signatures produced under that identity are bound to
//! its SHA3-256 public-key fingerprint (printed on every signed transcript).
//!
//! Operators wanting institutional trust register their verifier's
//! fingerprint with relying parties (regulators, auditors, counterparties)
//! out of band; relying parties then enforce a fingerprint allow-list.

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use std::path::{Path, PathBuf};

const PUBLIC_KEY_FILE: &str = "identity.public.b64";
const SECRET_KEY_FILE: &str = "identity.secret.b64";

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("could not resolve key directory: HOME unset and no --key-dir given")]
    NoKeyDir,

    #[error("io error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("key directory exists but only one of identity.public.b64 / identity.secret.b64 is present — refusing to overwrite at {dir}")]
    PartialKeypair { dir: String },

    #[error("invalid base64 in {file}")]
    Base64 { file: String },

    #[error("invalid key length in {file}")]
    InvalidKeyLength { file: String },
}

/// Resolve the key directory. Precedence:
///   1. `explicit` arg if Some.
///   2. `$H33_REPLAY_VERIFY_KEY_DIR` env var.
///   3. `$HOME/.h33-replay-verify/keys/`.
pub fn resolve_key_dir(explicit: Option<&Path>) -> Result<PathBuf, IdentityError> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Ok(v) = std::env::var("H33_REPLAY_VERIFY_KEY_DIR") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    let home = std::env::var("HOME").map_err(|_| IdentityError::NoKeyDir)?;
    Ok(PathBuf::from(home).join(".h33-replay-verify").join("keys"))
}

/// Result of [`load_or_create`] — both the keypair and a flag indicating
/// whether it was freshly created (so the CLI can announce the event).
#[derive(Debug)]
pub struct LoadedIdentity {
    pub public_key: mldsa65::PublicKey,
    pub secret_key: mldsa65::SecretKey,
    pub key_dir: PathBuf,
    pub freshly_created: bool,
}

/// Load an existing keypair from `dir`, or generate + persist a new one.
///
/// On unix the secret key file is written with mode 0600. On other platforms
/// the file is created with default permissions; operators should restrict
/// the parent directory themselves.
pub fn load_or_create(dir: &Path) -> Result<LoadedIdentity, IdentityError> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD;

    let pub_path = dir.join(PUBLIC_KEY_FILE);
    let sec_path = dir.join(SECRET_KEY_FILE);
    let pub_exists = pub_path.exists();
    let sec_exists = sec_path.exists();

    if pub_exists ^ sec_exists {
        return Err(IdentityError::PartialKeypair {
            dir: dir.display().to_string(),
        });
    }

    if pub_exists && sec_exists {
        let pub_b64 = std::fs::read_to_string(&pub_path).map_err(|e| IdentityError::Io {
            path: pub_path.display().to_string(),
            source: e,
        })?;
        let sec_b64 = std::fs::read_to_string(&sec_path).map_err(|e| IdentityError::Io {
            path: sec_path.display().to_string(),
            source: e,
        })?;
        let pub_bytes = b64
            .decode(pub_b64.trim())
            .map_err(|_| IdentityError::Base64 {
                file: pub_path.display().to_string(),
            })?;
        let sec_bytes = b64
            .decode(sec_b64.trim())
            .map_err(|_| IdentityError::Base64 {
                file: sec_path.display().to_string(),
            })?;
        let public_key =
            mldsa65::PublicKey::from_bytes(&pub_bytes).map_err(|_| IdentityError::InvalidKeyLength {
                file: pub_path.display().to_string(),
            })?;
        let secret_key =
            mldsa65::SecretKey::from_bytes(&sec_bytes).map_err(|_| IdentityError::InvalidKeyLength {
                file: sec_path.display().to_string(),
            })?;
        return Ok(LoadedIdentity {
            public_key,
            secret_key,
            key_dir: dir.to_path_buf(),
            freshly_created: false,
        });
    }

    // Generate fresh.
    std::fs::create_dir_all(dir).map_err(|e| IdentityError::Io {
        path: dir.display().to_string(),
        source: e,
    })?;
    let (pk, sk) = mldsa65::keypair();
    let pk_b64 = b64.encode(pk.as_bytes());
    let sk_b64 = b64.encode(sk.as_bytes());

    std::fs::write(&pub_path, &pk_b64).map_err(|e| IdentityError::Io {
        path: pub_path.display().to_string(),
        source: e,
    })?;
    write_secret_file(&sec_path, sk_b64.as_bytes())?;

    Ok(LoadedIdentity {
        public_key: pk,
        secret_key: sk,
        key_dir: dir.to_path_buf(),
        freshly_created: true,
    })
}

#[cfg(unix)]
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<(), IdentityError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| IdentityError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
    f.write_all(contents).map_err(|e| IdentityError::Io {
        path: path.display().to_string(),
        source: e,
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<(), IdentityError> {
    std::fs::write(path, contents).map_err(|e| IdentityError::Io {
        path: path.display().to_string(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_then_load_round_trip() {
        use sha3::{Digest, Sha3_256};
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("keys");

        let first = load_or_create(&dir).expect("first");
        assert!(first.freshly_created);
        let fp_first = Sha3_256::new()
            .chain_update(first.public_key.as_bytes())
            .finalize();

        let second = load_or_create(&dir).expect("second");
        assert!(!second.freshly_created);
        let fp_second = Sha3_256::new()
            .chain_update(second.public_key.as_bytes())
            .finalize();

        assert_eq!(fp_first.as_slice(), fp_second.as_slice());
    }

    #[test]
    fn partial_keypair_refuses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("keys");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(PUBLIC_KEY_FILE), "anything").unwrap();
        let err = load_or_create(&dir).unwrap_err();
        assert!(matches!(err, IdentityError::PartialKeypair { .. }));
    }
}
