//! # EVO-OMAP Private Tuning
//!
//! This module contains the **private configuration parameters** that define
//! the specific tuning choices for this implementation.
//!
//! ## WARNING
//!
//! These values represent specific tuning choices that could be targeted
//! by attackers if published. **Do not share or publish these exact values.**

#[allow(unused_imports)]
use crate::public_spec::STATE_SIZE;

// =============================================================================
// Private Configuration
// =============================================================================

/// Private tuning parameters for EVO-OMAP.
///
/// This struct holds the specific values that define how this implementation
/// behaves. These values should remain private and not be published.
pub mod config {
    use crate::public_spec::{
        DatasetSpec,
        PROGRAM_LENGTH_MIN, PROGRAM_LENGTH_MAX,
        BRANCH_WAYS_MIN, BRANCH_WAYS_MAX,
        STEPS_MIN, STEPS_MAX,
        EPOCH_LENGTH_MIN, EPOCH_LENGTH_MAX,
    };

    /// Configuration preset for standard deployment.
    pub struct PrivateConfig {
        pub node_size: usize,
        pub num_nodes: usize,
        pub cache_size: usize,
        pub compute_steps: usize,
        pub program_length: usize,
        pub epoch_length: u64,
        pub branch_ways: u8,
        pub cache_block_size: usize,
        pub cache_num_blocks: usize,
    }

    impl PrivateConfig {
        /// Creates the standard configuration.
        pub fn standard() -> Self {
            Self {
                node_size: 1_048_576,
                num_nodes: 256,
                cache_size: 33_554_432,
                compute_steps: 4_096,
                program_length: 8,
                epoch_length: 1_024,
                branch_ways: 4,
                cache_block_size: 65_536,
                cache_num_blocks: 512,
            }
        }

        /// Creates a memory-hard configuration.
        pub fn mem_hard() -> Self {
            Self {
                node_size: 2_097_152,
                num_nodes: 512,
                cache_size: 67_108_864,
                compute_steps: 8_192,
                program_length: 8,
                epoch_length: 512,
                branch_ways: 4,
                cache_block_size: 65_536,
                cache_num_blocks: 1024,
            }
        }

        /// Creates a fast/lightweight configuration.
        pub fn fast() -> Self {
            Self {
                node_size: 524_288,
                num_nodes: 128,
                cache_size: 16_777_216,
                compute_steps: 2_048,
                program_length: 8,
                epoch_length: 2_048,
                branch_ways: 4,
                cache_block_size: 65_536,
                cache_num_blocks: 256,
            }
        }

        /// Validates that all parameters are within public spec ranges.
        pub fn validate(&self) -> Result<(), String> {
            if self.node_size < DatasetSpec::NODE_SIZE_MIN
                || self.node_size > DatasetSpec::NODE_SIZE_MAX
            {
                return Err(format!(
                    "node_size {} outside valid range [{}, {}]",
                    self.node_size, DatasetSpec::NODE_SIZE_MIN, DatasetSpec::NODE_SIZE_MAX
                ));
            }

            if self.num_nodes < DatasetSpec::NUM_NODES_MIN
                || self.num_nodes > DatasetSpec::NUM_NODES_MAX
            {
                return Err(format!(
                    "num_nodes {} outside valid range [{}, {}]",
                    self.num_nodes, DatasetSpec::NUM_NODES_MIN, DatasetSpec::NUM_NODES_MAX
                ));
            }

            let total_memory = self.node_size * self.num_nodes;
            if total_memory < DatasetSpec::MEMORY_MIN
                || total_memory > DatasetSpec::MEMORY_MAX
            {
                return Err(format!(
                    "total_memory {} outside valid range [{}, {}]",
                    total_memory, DatasetSpec::MEMORY_MIN, DatasetSpec::MEMORY_MAX
                ));
            }

            if self.compute_steps < STEPS_MIN || self.compute_steps > STEPS_MAX {
                return Err(format!(
                    "compute_steps {} outside valid range [{}, {}]",
                    self.compute_steps, STEPS_MIN, STEPS_MAX
                ));
            }

            if self.program_length < PROGRAM_LENGTH_MIN
                || self.program_length > PROGRAM_LENGTH_MAX
            {
                return Err(format!(
                    "program_length {} outside valid range [{}, {}]",
                    self.program_length, PROGRAM_LENGTH_MIN, PROGRAM_LENGTH_MAX
                ));
            }

            if self.epoch_length < EPOCH_LENGTH_MIN || self.epoch_length > EPOCH_LENGTH_MAX {
                return Err(format!(
                    "epoch_length {} outside valid range [{}, {}]",
                    self.epoch_length, EPOCH_LENGTH_MIN, EPOCH_LENGTH_MAX
                ));
            }

            if self.branch_ways < BRANCH_WAYS_MIN || self.branch_ways > BRANCH_WAYS_MAX {
                return Err(format!(
                    "branch_ways {} outside valid range [{}, {}]",
                    self.branch_ways, BRANCH_WAYS_MIN, BRANCH_WAYS_MAX
                ));
            }

            Ok(())
        }

        /// Calculates total dataset memory requirement.
        pub fn total_memory(&self) -> usize {
            self.node_size * self.num_nodes
        }

        /// Calculates the ratio of dataset memory to cache memory.
        pub fn memory_commitment_ratio(&self) -> usize {
            self.total_memory() / self.cache_size
        }
    }
}

// =============================================================================
// Internal Constants
// =============================================================================

/// Internal constants for the implementation.
pub(crate) mod constants {
    pub const NODE_SIZE: usize = 1_048_576;
    pub const NUM_NODES: usize = 256;
    pub const CACHE_SIZE: usize = 33_554_432;
    pub const NUM_STEPS: usize = 4_096;
    pub const PROGRAM_LENGTH: usize = 8;
    pub const EPOCH_LENGTH: u64 = 1_024;
    pub const STATE_SIZE: usize = crate::public_spec::STATE_SIZE;
    pub const CACHE_BLOCK_SIZE: usize = 65_536;
    pub const CACHE_NUM_BLOCKS: usize = 512;
}
