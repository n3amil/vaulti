//! Reading and atomically writing the vault file.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::Result;
use crate::vault::VaultFile;

pub fn load(path: &Path) -> Result<VaultFile> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Writes to a temp file next to `path`, fsyncs, then renames over the
/// original, so a crash never leaves a half-written vault. Mode 0600 on Unix.
pub fn save(path: &Path, file: &VaultFile) -> Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let json = serde_json::to_vec_pretty(file)?;

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(&json)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KdfParams, Vault};

    #[test]
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/vault.json");
        let (v, _) = Vault::create("pw", KdfParams::insecure_fast()).unwrap();
        save(&path, &v.to_file().unwrap()).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.vault_id, v.vault_id());
        assert!(Vault::unlock(loaded, "pw").is_ok());
        assert!(!path.with_extension("tmp").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
