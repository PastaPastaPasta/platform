use crate::drive::Drive;
use crate::error::Error;
use dpp::util::deserializer::ProtocolVersion;
use grovedb::TransactionArg;
use nohash_hasher::IntMap;
use platform_version::version::drive_versions::DriveVersion;

/// ProtocolVersion cache that handles both global and block data
#[derive(Default)]
pub struct ProtocolVersionsCache {
    /// The current global cache for protocol versions
    // TODO: If we persist this in the state and it should be loaded for correct
    //  use then it's not actually the cache. Move out of cache because it's confusing
    pub global_cache: IntMap<ProtocolVersion, u64>,
    block_cache: IntMap<ProtocolVersion, u64>,
    loaded: bool,
    needs_wipe: bool,
}

#[cfg(feature = "full")]
impl ProtocolVersionsCache {
    /// Create a new ProtocolVersionsCache instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the protocol versions cache from disk if needed
    pub fn load_if_needed(
        &mut self,
        drive: &Drive,
        transaction: TransactionArg,
        drive_version: &DriveVersion,
    ) -> Result<(), Error> {
        if !self.loaded {
            self.global_cache = drive.fetch_versions_with_counter(transaction, drive_version)?;
            self.loaded = true;
        };
        Ok(())
    }

    /// Sets the protocol version to the block cache
    pub fn set_block_cache_version_count(&mut self, version: ProtocolVersion, count: u64) {
        self.block_cache.insert(version, count);
    }

    /// Tries to get a version from block cache if present
    /// if block cache doesn't have the version set
    /// then it tries get the version from global cache
    pub fn get(&self, version: &ProtocolVersion) -> Option<&u64> {
        if let Some(count) = self.block_cache.get(version) {
            Some(count)
        } else {
            self.global_cache.get(version)
        }
    }

    /// Merge block cache to global cache
    pub fn merge_block_cache(&mut self) {
        if self.needs_wipe {
            self.global_cache.clear();
            self.block_cache.clear();
            self.needs_wipe = false;
        } else {
            self.global_cache.extend(self.block_cache.drain());
        }
    }

    /// Clear block cache
    pub fn clear_block_cache(&mut self) {
        self.block_cache.clear()
    }

    /// Versions passing threshold
    pub fn versions_passing_threshold(
        &mut self,
        required_upgraded_hpns: u64,
    ) -> Vec<ProtocolVersion> {
        self.needs_wipe = true;
        let mut cache = self.global_cache.clone();

        cache.extend(self.block_cache.drain());
        cache
            .into_iter()
            .filter_map(|(protocol_version, count)| {
                if count >= required_upgraded_hpns {
                    Some(protocol_version)
                } else {
                    None
                }
            })
            .collect::<Vec<ProtocolVersion>>()
    }
}
