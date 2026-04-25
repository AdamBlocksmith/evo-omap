pub mod hash;
pub mod public_spec;
pub mod constants;
pub mod evo_omap;

pub use hash::{Hash, blake3_256, blake3_xof, blake3_xof_multi, sha3_256};

pub use evo_omap::{
    State, Instruction, Program, Dataset, CowDataset,
    compute_epoch_seed,
    evo_omap_hash, evo_omap_hash_with_buffers, evo_omap_hash_light,
    LightDataset,
    mine, mine_parallel, verify, verify_light,
    derive_indices, execute_program, apply_branch, apply_branch_with_buffer, generate_program,
    compute_memory_commitment, generate_dataset,
    DatasetCache, HashBuffers,
    DatasetSpec,
    STATE_SIZE_SPEC,
    PROGRAM_LENGTH_MIN, PROGRAM_LENGTH_MAX,
    BRANCH_WAYS_MIN, BRANCH_WAYS_MAX,
    STEPS_MIN, STEPS_MAX,
    EPOCH_LENGTH_MIN, EPOCH_LENGTH_MAX,
    DOMAIN_EPOCH, DOMAIN_NODE, DOMAIN_SEED,
    DOMAIN_CACHE, DOMAIN_BRANCH, DOMAIN_COMMITMENT, DOMAIN_MEMORY,
};

pub use rayon::prelude::*;
pub use rayon::current_num_threads;
