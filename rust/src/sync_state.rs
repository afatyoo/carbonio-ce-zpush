use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// One (user, device, collection) -> SyncKey counter, in the shape written
/// to and read from the on-disk snapshot. JSON object keys must be strings,
/// so the (user, device_id, collection_id) tuple is flattened into fields
/// instead of being used as a map key directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedEntry {
    user: String,
    device_id: String,
    collection_id: String,
    key: u64,
}

/// SyncKey state per (user, device id, collection id): a real monotonic
/// counter per client/collection, optionally snapshotted to a JSON file
/// after every change so a server restart does not force every device
/// back into a fresh FolderSync.
pub struct SyncStateStore {
    keys: Mutex<HashMap<(String, String, String), u64>>,
    persist_path: Option<String>,
}

impl SyncStateStore {
    /// In-memory only; state is lost on restart. Used by tests and when no
    /// persistence path is configured.
    pub fn new() -> Self {
        Self { keys: Mutex::new(HashMap::new()), persist_path: None }
    }

    /// Loads existing state from `path` if it exists (a missing file is not
    /// an error, just an empty starting state), and snapshots every change
    /// back to that same path.
    pub fn load_or_create(path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        let keys = match std::fs::read_to_string(&path) {
            Ok(contents) => {
                let entries: Vec<PersistedEntry> =
                    serde_json::from_str(&contents).with_context(|| format!("failed to parse sync state file at {path}"))?;
                entries
                    .into_iter()
                    .map(|e| ((e.user, e.device_id, e.collection_id), e.key))
                    .collect()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e).with_context(|| format!("failed to read sync state file at {path}")),
        };
        Ok(Self { keys: Mutex::new(keys), persist_path: Some(path) })
    }

    /// Returns the current SyncKey for this (user, device, collection),
    /// `"0"` if it has never synced before (per MS-ASCMD, SyncKey "0" means
    /// "start a fresh sync").
    pub fn current_key(&self, user: &str, device_id: &str, collection_id: &str) -> String {
        let keys = self.keys.lock().expect("sync state mutex poisoned");
        keys.get(&(user.to_string(), device_id.to_string(), collection_id.to_string()))
            .map(|n| n.to_string())
            .unwrap_or_else(|| "0".to_string())
    }

    /// Advances and returns the next SyncKey for this (user, device,
    /// collection), to hand back to the device as the new SyncKey. If this
    /// store was created with [`Self::load_or_create`], also snapshots the
    /// updated state to disk; a write failure is logged, not fatal, since
    /// losing the latest snapshot is recoverable (worst case: one extra
    /// FolderSync after a crash) and should not break a live sync reply.
    pub fn advance_key(&self, user: &str, device_id: &str, collection_id: &str) -> String {
        let new_key = {
            let mut keys = self.keys.lock().expect("sync state mutex poisoned");
            let entry = keys
                .entry((user.to_string(), device_id.to_string(), collection_id.to_string()))
                .or_insert(0);
            *entry += 1;
            *entry
        };
        self.persist_and_return(new_key)
    }

    /// Sets the SyncKey for this (user, device, collection) to an exact
    /// value instead of incrementing it, for collections whose "key" is
    /// really an opaque token from elsewhere (Carbonio's own `SyncRequest`
    /// token, for email's real delta sync) rather than a counter this store
    /// owns. Same persistence behavior as [`Self::advance_key`].
    pub fn set_key(&self, user: &str, device_id: &str, collection_id: &str, key: u64) -> String {
        {
            let mut keys = self.keys.lock().expect("sync state mutex poisoned");
            keys.insert((user.to_string(), device_id.to_string(), collection_id.to_string()), key);
        }
        self.persist_and_return(key)
    }

    fn persist_and_return(&self, key: u64) -> String {
        if let Some(path) = &self.persist_path {
            let entries: Vec<PersistedEntry> = {
                let keys = self.keys.lock().expect("sync state mutex poisoned");
                keys.iter()
                    .map(|((u, d, c), k)| PersistedEntry {
                        user: u.clone(),
                        device_id: d.clone(),
                        collection_id: c.clone(),
                        key: *k,
                    })
                    .collect()
            };
            if let Err(e) = write_snapshot(path, &entries) {
                eprintln!("[sync_state] failed to persist snapshot to {path}: {e:?}");
            }
        }
        key.to_string()
    }
}

/// Writes `entries` to `path` via a temp file + rename, so a crash mid-write
/// never leaves a half-written, unparseable state file behind.
fn write_snapshot(path: &str, entries: &[PersistedEntry]) -> Result<()> {
    let tmp_path = format!("{path}.tmp");
    let json = serde_json::to_string(entries).context("failed to serialize sync state")?;
    std::fs::write(&tmp_path, json).with_context(|| format!("failed to write {tmp_path}"))?;
    std::fs::rename(&tmp_path, path).with_context(|| format!("failed to rename {tmp_path} to {path}"))?;
    Ok(())
}

impl Default for SyncStateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_collection_starts_at_sync_key_zero() {
        let store = SyncStateStore::new();
        assert_eq!(store.current_key("alice", "DEV1", "2"), "0");
    }

    #[test]
    fn advancing_increments_and_persists_for_the_same_key() {
        let store = SyncStateStore::new();
        assert_eq!(store.advance_key("alice", "DEV1", "2"), "1");
        assert_eq!(store.current_key("alice", "DEV1", "2"), "1");
        assert_eq!(store.advance_key("alice", "DEV1", "2"), "2");
    }

    #[test]
    fn set_key_jumps_straight_to_an_exact_value_and_persists() {
        let store = SyncStateStore::new();
        assert_eq!(store.set_key("alice", "DEV1", "2", 190), "190");
        assert_eq!(store.current_key("alice", "DEV1", "2"), "190");
        assert_eq!(store.set_key("alice", "DEV1", "2", 192), "192");
        assert_eq!(store.current_key("alice", "DEV1", "2"), "192");
    }

    #[test]
    fn different_collections_and_devices_track_independently() {
        let store = SyncStateStore::new();
        store.advance_key("alice", "DEV1", "2");
        store.advance_key("alice", "DEV1", "2");
        assert_eq!(store.current_key("alice", "DEV1", "2"), "2");
        assert_eq!(store.current_key("alice", "DEV2", "2"), "0");
        assert_eq!(store.current_key("alice", "DEV1", "3"), "0");
    }

    #[test]
    fn missing_persistence_file_starts_empty_not_an_error() {
        let path = std::env::temp_dir().join(format!("carbonio-ce-zpush-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let store = SyncStateStore::load_or_create(path.to_str().unwrap()).unwrap();
        assert_eq!(store.current_key("alice", "DEV1", "2"), "0");
    }

    #[test]
    fn state_survives_a_simulated_restart_via_the_same_file() {
        let path = std::env::temp_dir().join(format!("carbonio-ce-zpush-test-restart-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let path_str = path.to_str().unwrap();

        {
            let store = SyncStateStore::load_or_create(path_str).unwrap();
            store.advance_key("alice", "DEV1", "2");
            store.advance_key("alice", "DEV1", "2");
        }

        // Simulate a fresh process: load the same file again.
        let reloaded = SyncStateStore::load_or_create(path_str).unwrap();
        assert_eq!(reloaded.current_key("alice", "DEV1", "2"), "2");

        std::fs::remove_file(&path).ok();
    }
}
