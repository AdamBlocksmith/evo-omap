//! # EVO-OMAP Public Constants
//!
//! This module contains all public protocol constants for EVO-OMAP.
//! These are intentionally public as part of the open protocol specification.

// Re-export algorithm-level constants from public_spec
pub use crate::public_spec::NUM_REGISTERS;
pub use crate::public_spec::OPERAND_WORDS;
pub use crate::public_spec::STATE_SIZE;

// =============================================================================
// Dataset & Memory Parameters
// =============================================================================

/// Size of each dataset node in bytes (1 MiB).
pub const NODE_SIZE: usize = 1_048_576;

/// Number of nodes in the dataset (256 nodes = 256 MiB total).
pub const NUM_NODES: usize = 256;

/// Cache size for light verification (32 MiB).
pub const CACHE_SIZE: usize = 33_554_432;

/// Number of compute steps per hash (controls memory access depth).
pub const NUM_STEPS: usize = 4_096;

// =============================================================================
// Program Execution Parameters
// =============================================================================

/// Number of instructions per program.
pub const PROGRAM_LENGTH: usize = 8;

// =============================================================================
// Epoch Parameters
// =============================================================================

/// Number of blocks per epoch (dataset regenerates at epoch boundary).
pub const EPOCH_LENGTH: u64 = 1_024;

// =============================================================================
// Program Generation Bit Fields
// =============================================================================

/// Bit mask for source register field (7 bits, values 0-127).
pub const SRC_MASK: u64 = 0x7F;

// =============================================================================
// Branch Parameters
// =============================================================================

/// Number of branch variants (4 ways: 0, 1, 2, 3).
pub const BRANCH_WAYS: usize = 4;

/// Bit mask for branch variant selection.
pub const BRANCH_MASK: u64 = (BRANCH_WAYS - 1) as u64;

// =============================================================================
// Data Slice Sizes
// =============================================================================

/// Number of bytes of node data mixed into branch input (32 bytes).
pub const BRANCH_NODE_PREFIX: usize = 32;

/// Number of bytes of node data used in write operation (8 KiB).
pub const WRITE_NODE_PREFIX: usize = 8_192;

/// Number of bytes of state mixed in various operations (32 bytes = 256 bits).
pub const STATE_HASH_PREFIX: usize = 32;

// =============================================================================
// Cache Parameters
// =============================================================================

/// Cache block size in bytes (64 KiB).
pub const CACHE_BLOCK_SIZE: usize = 65_536;

/// Number of cache blocks (512 blocks × 64 KiB = 32 MiB).
pub const CACHE_NUM_BLOCKS: usize = 512;