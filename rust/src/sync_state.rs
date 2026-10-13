use std::collections::HashMap;
use std::sync::Mutex;

/// In-memory, process-lifetime sync state: one SyncKey counter per
/// (user, device id, collection id). This is a real monotonic counter per
/// client/collection, not a stub, but it does not survive a server
/// restart, so a restart forces every device into a fresh FolderSync.
/// Persisting this to disk (sqlite, a flat file per the PHP backend's
/// "sqlstatemachine", etc.) is tracked separately and not done yet.
pub struct SyncStateStore {
    keys: Mutex<HashMap<(String, String, String), u64>>,
}

impl SyncStateStore {
    pub fn new() -> Self {
        Self { keys: Mutex::new(HashMap::new()) }
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
    /// collection), to hand back to the device as the new SyncKey.
    pub fn advance_key(&self, user: &str, device_id: &str, collection_id: &str) -> String {
        let mut keys = self.keys.lock().expect("sync state mutex poisoned");
        let entry = keys
            .entry((user.to_string(), device_id.to_string(), collection_id.to_string()))
            .or_insert(0);
        *entry += 1;
        entry.to_string()
    }
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
    fn different_collections_and_devices_track_independently() {
        let store = SyncStateStore::new();
        store.advance_key("alice", "DEV1", "2");
        store.advance_key("alice", "DEV1", "2");
        assert_eq!(store.current_key("alice", "DEV1", "2"), "2");
        assert_eq!(store.current_key("alice", "DEV2", "2"), "0");
        assert_eq!(store.current_key("alice", "DEV1", "3"), "0");
    }
}
