use std::{
    fs::{self, File, OpenOptions, TryLockError},
    io::{self, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

pub const STATE_LEASE_SCHEMA_VERSION: u16 = 1;
const MAX_STATE_LEASE_METADATA_BYTES: usize = 128;

/// Process-lifetime exclusive lease for the single-writer durable state set.
///
/// The file remains on disk, but the operating-system lock is released when
/// the process exits or crashes. Its contents are bounded operator metadata,
/// not authoritative runtime state.
#[derive(Debug)]
pub struct DurableStateLease {
    file: File,
    path: PathBuf,
}

impl DurableStateLease {
    pub fn acquire_for_policy_state(policy_state_path: &Path) -> io::Result<Self> {
        Self::acquire(state_lease_path(policy_state_path))
    }

    fn acquire(path: PathBuf) -> io::Result<Self> {
        if let Some(parent) = meaningful_parent(&path) {
            fs::create_dir_all(parent)?;
        }

        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "durable state writer lease `{}` must be a regular file",
                    path.display()
                ),
            ));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }

        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "durable state already has an active writer holding `{}`",
                        path.display()
                    ),
                ));
            }
            Err(TryLockError::Error(error)) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "could not acquire durable state writer lease `{}`: {error}",
                        path.display()
                    ),
                ));
            }
        }

        let metadata = format!(
            "{{\"schema_version\":{},\"pid\":{}}}\n",
            STATE_LEASE_SCHEMA_VERSION,
            std::process::id()
        );
        if metadata.len() > MAX_STATE_LEASE_METADATA_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "durable state lease metadata exceeded its fixed bound",
            ));
        }
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(metadata.as_bytes())?;
        file.sync_all()?;

        Ok(Self { file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for DurableStateLease {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

pub fn state_lease_path(policy_state_path: &Path) -> PathBuf {
    let mut path = policy_state_path.as_os_str().to_os_string();
    path.push(".lock");
    PathBuf::from(path)
}

fn meaningful_parent(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn unique_temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("eidolon-state-lease-{label}-{}", Uuid::new_v4()))
    }

    #[test]
    fn overlapping_writer_fails_closed_until_lease_is_released() {
        let state_path = unique_temp_path("overlap");
        let first = DurableStateLease::acquire_for_policy_state(&state_path).expect("first lease");

        let error = DurableStateLease::acquire_for_policy_state(&state_path)
            .expect_err("overlapping writer must fail");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(error.to_string().contains("active writer"));

        drop(first);
        let restarted = DurableStateLease::acquire_for_policy_state(&state_path)
            .expect("restart should reacquire lease");
        let lock_path = restarted.path().to_path_buf();
        drop(restarted);
        fs::remove_file(lock_path).expect("lock file should remove");
    }

    #[test]
    fn stale_metadata_is_rewritten_to_a_bounded_record() {
        let state_path = unique_temp_path("metadata");
        let lock_path = state_lease_path(&state_path);
        fs::write(&lock_path, vec![b'x'; 4096]).expect("stale lock metadata should write");

        let lease =
            DurableStateLease::acquire_for_policy_state(&state_path).expect("lease should open");
        let metadata = fs::read(lease.path()).expect("lease metadata should read");
        assert!(metadata.len() <= MAX_STATE_LEASE_METADATA_BYTES);
        let value: serde_json::Value =
            serde_json::from_slice(&metadata).expect("lease metadata should be valid JSON");
        assert_eq!(
            value["schema_version"],
            serde_json::json!(STATE_LEASE_SCHEMA_VERSION)
        );
        assert_eq!(value["pid"], serde_json::json!(std::process::id()));

        drop(lease);
        fs::remove_file(lock_path).expect("lock file should remove");
    }

    #[test]
    fn unavailable_lock_parent_fails_startup() {
        let parent = unique_temp_path("unavailable-parent");
        fs::write(&parent, b"not a directory").expect("parent fixture should write");
        let state_path = parent.join("policy-state.json");

        let error = DurableStateLease::acquire_for_policy_state(&state_path)
            .expect_err("unavailable lease storage must fail");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::AlreadyExists | io::ErrorKind::NotADirectory
        ));

        fs::remove_file(parent).expect("parent fixture should remove");
    }

    #[cfg(unix)]
    #[test]
    fn lease_symlink_is_rejected_without_mutating_its_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let state_path = unique_temp_path("symlink");
        let lock_path = state_lease_path(&state_path);
        let victim_path = unique_temp_path("symlink-victim");
        let victim_before = b"victim-must-remain-unchanged";
        fs::write(&victim_path, victim_before).expect("victim fixture should write");
        fs::set_permissions(&victim_path, fs::Permissions::from_mode(0o640))
            .expect("victim permissions should set");
        symlink(&victim_path, &lock_path).expect("lease symlink should create");

        DurableStateLease::acquire_for_policy_state(&state_path)
            .expect_err("lease symlink must fail closed");

        assert_eq!(fs::read(&victim_path).unwrap(), victim_before);
        assert_eq!(
            fs::metadata(&victim_path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert!(fs::symlink_metadata(&lock_path)
            .unwrap()
            .file_type()
            .is_symlink());

        fs::remove_file(lock_path).expect("lease symlink should remove");
        fs::remove_file(victim_path).expect("victim fixture should remove");
    }

    #[cfg(unix)]
    #[test]
    fn lease_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let state_path = unique_temp_path("permissions");
        let lease =
            DurableStateLease::acquire_for_policy_state(&state_path).expect("lease should open");
        let mode = fs::metadata(lease.path())
            .expect("lease metadata should read")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        let lock_path = lease.path().to_path_buf();
        drop(lease);
        fs::remove_file(lock_path).expect("lock file should remove");
    }
}
