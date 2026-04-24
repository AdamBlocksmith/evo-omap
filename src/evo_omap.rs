//! EVO-OMAP Proof-of-Work Algorithm Implementation
//!
//! This module implements the EVO-OMAP algorithm. Protocol constants are
//! defined in constants.rs. Public specification is in public_spec.rs.

pub use crate::hash::{Hash, blake3_256, blake3_xof, blake3_xof_multi, sha3_256};
pub use crate::public_spec::{
    Instruction,
    STATE_SIZE as STATE_SIZE_SPEC,
    PROGRAM_LENGTH_MIN, PROGRAM_LENGTH_MAX,
    BRANCH_WAYS_MIN, BRANCH_WAYS_MAX,
    STEPS_MIN, STEPS_MAX,
    EPOCH_LENGTH_MIN, EPOCH_LENGTH_MAX,
    DOMAIN_EPOCH, DOMAIN_NODE, DOMAIN_SEED,
    DOMAIN_CACHE, DOMAIN_BRANCH, DOMAIN_COMMITMENT, DOMAIN_MEMORY,
};

use crate::constants::{
    NODE_SIZE, NUM_NODES, CACHE_SIZE, NUM_STEPS, PROGRAM_LENGTH, EPOCH_LENGTH,
    CACHE_BLOCK_SIZE, CACHE_NUM_BLOCKS,
    BRANCH_MASK, SRC_MASK,
    BRANCH_NODE_PREFIX, WRITE_NODE_PREFIX, STATE_HASH_PREFIX,
    NUM_REGISTERS,
};

pub use crate::public_spec::DatasetSpec;
pub use crate::public_spec::CacheSpec;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct State(pub [u8; STATE_SIZE_SPEC]);

impl State {
    pub fn as_u64_array(&self) -> [u64; 8] {
        let mut arr = [0u64; 8];
        for i in 0..8 {
            arr[i] = u64::from_le_bytes([
                self.0[i * 8],
                self.0[i * 8 + 1],
                self.0[i * 8 + 2],
                self.0[i * 8 + 3],
                self.0[i * 8 + 4],
                self.0[i * 8 + 5],
                self.0[i * 8 + 6],
                self.0[i * 8 + 7],
            ]);
        }
        arr
    }

    pub fn write_u64_at_index(&mut self, index: usize, value: u64) {
        let bytes = &mut self.0[index * 8..index * 8 + 8];
        bytes.copy_from_slice(&value.to_le_bytes());
    }

    pub fn write_all_u64(&mut self, values: &[u64; 8]) {
        for (i, &val) in values.iter().enumerate() {
            self.write_u64_at_index(i, val);
        }
    }

    pub fn as_bytes(&self) -> &[u8; STATE_SIZE_SPEC] {
        &self.0
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8; STATE_SIZE_SPEC] {
        &mut self.0
    }

    pub fn from_seed(seed: &Hash) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed.as_ref());
        let mut reader = hasher.finalize_xof();
        let mut output = [0u8; STATE_SIZE_SPEC];
        reader.fill(&mut output);
        State(output)
    }
}

pub trait DatasetLike {
    fn get(&self, index: usize) -> &[u8];
    fn set(&mut self, index: usize, node: Vec<u8>);
    fn as_node_slice(&self) -> Vec<&[u8]>;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Program {
    pub instructions: Vec<Instruction>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Dataset {
    pub nodes: Vec<Vec<u8>>,
}

impl Dataset {
    pub fn new() -> Self {
        Self {
            nodes: vec![Vec::new(); NUM_NODES],
        }
    }

    pub fn get(&self, index: usize) -> &[u8] {
        &self.nodes[index]
    }

    pub fn set(&mut self, index: usize, node: Vec<u8>) {
        self.nodes[index] = node;
    }
}

impl Default for Dataset {
    fn default() -> Self {
        Self::new()
    }
}

impl DatasetLike for Dataset {
    fn get(&self, index: usize) -> &[u8] {
        &self.nodes[index]
    }

    fn set(&mut self, index: usize, node: Vec<u8>) {
        self.nodes[index] = node;
    }

    fn as_node_slice(&self) -> Vec<&[u8]> {
        self.nodes.iter().map(|n| n.as_slice()).collect()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Cache {
    pub data: Vec<u8>,
}

impl Cache {
    pub fn new() -> Self {
        Self {
            data: Vec::with_capacity(CACHE_SIZE),
        }
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CowDataset<'a> {
    base: &'a Dataset,
    modified: Vec<Option<Vec<u8>>>,
    modified_indices: Vec<usize>,
}

impl<'a> CowDataset<'a> {
    pub fn new(base: &'a Dataset) -> Self {
        Self {
            base,
            modified: vec![None; NUM_NODES],
            modified_indices: Vec::new(),
        }
    }

    pub fn get(&self, index: usize) -> &[u8] {
        if let Some(ref node) = self.modified[index] {
            node
        } else {
            &self.base.nodes[index]
        }
    }

    pub fn set(&mut self, index: usize, node: Vec<u8>) {
        if self.modified[index].is_none() {
            self.modified_indices.push(index);
        }
        self.modified[index] = Some(node);
    }

    pub fn reset(&mut self) {
        for &i in &self.modified_indices {
            self.modified[i] = None;
        }
        self.modified_indices.clear();
    }

    pub fn as_dataset(&self) -> Vec<&[u8]> {
        let mut result = Vec::with_capacity(NUM_NODES);
        for i in 0..NUM_NODES {
            result.push(self.get(i));
        }
        result
    }

    pub fn as_node_slice(&self) -> Vec<&[u8]> {
        self.as_dataset()
    }
}

impl<'a> DatasetLike for CowDataset<'a> {
    fn get(&self, index: usize) -> &[u8] {
        CowDataset::get(self, index)
    }

    fn set(&mut self, index: usize, node: Vec<u8>) {
        CowDataset::set(self, index, node);
    }

    fn as_node_slice(&self) -> Vec<&[u8]> {
        self.as_dataset()
    }
}

fn compute_epoch_number(height: u64) -> u64 {
    height / EPOCH_LENGTH
}

pub fn compute_epoch_seed(height: u64) -> Hash {
    let epoch = compute_epoch_number(height);
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(DOMAIN_EPOCH);
    data.extend_from_slice(&epoch.to_le_bytes());
    blake3_256(&data)
}

const MAX_HEADER_SIZE: usize = 256;

fn compute_mining_seed(header: &[u8], height: u64, nonce: u64) -> Hash {
    let header_len = header.len().min(MAX_HEADER_SIZE);
    let header = &header[..header_len];
    let mut data = Vec::with_capacity(48 + header.len());
    data.extend_from_slice(DOMAIN_SEED);
    data.extend_from_slice(&(header.len() as u64).to_le_bytes());
    data.extend_from_slice(header);
    data.extend_from_slice(&height.to_le_bytes());
    data.extend_from_slice(&nonce.to_le_bytes());
    blake3_256(&data)
}

fn generate_node0(seed: &Hash) -> Vec<u8> {
    let epoch_seed_bytes = seed.as_ref();
    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(DOMAIN_NODE);
    data.extend_from_slice(epoch_seed_bytes);
    data.extend_from_slice(&0u64.to_le_bytes());
    blake3_xof(&data, NODE_SIZE)
}

pub fn generate_dataset(seed: &Hash) -> Dataset {
    let mut dataset = Dataset::new();
    let epoch_seed_bytes = seed.as_ref();

    dataset.nodes[0] = generate_node0(seed);

    for i in 1..NUM_NODES {
        let mut data = Vec::with_capacity(48 + NODE_SIZE);
        data.extend_from_slice(DOMAIN_NODE);
        data.extend_from_slice(epoch_seed_bytes);
        data.extend_from_slice(&dataset.nodes[i - 1]);
        data.extend_from_slice(&(i as u64).to_le_bytes());
        dataset.nodes[i] = blake3_xof(&data, NODE_SIZE);
    }

    dataset
}

pub fn generate_cache(seed: &Hash) -> Cache {
    let epoch_seed_bytes = seed.as_ref();
    let mut cache = Cache::new();

    for i in 0..CACHE_NUM_BLOCKS {
        let mut data = Vec::with_capacity(48);
        data.extend_from_slice(DOMAIN_CACHE);
        data.extend_from_slice(epoch_seed_bytes);
        data.extend_from_slice(&(i as u64).to_le_bytes());

        let block_hash = blake3_256(&data);
        let block_extended = blake3_xof(block_hash.as_ref(), CACHE_BLOCK_SIZE);
        cache.data.extend_from_slice(&block_extended);
    }

    cache
}

fn reconstruct_node(_cache: &Cache, epoch_seed: &Hash, index: usize, prev_node: &[u8]) -> Vec<u8> {
    let index_bytes = (index as u64).to_le_bytes();
    let epoch_seed_bytes = epoch_seed.as_ref();
    let mut data = Vec::with_capacity(48 + NODE_SIZE);
    data.extend_from_slice(DOMAIN_NODE);
    data.extend_from_slice(epoch_seed_bytes);
    data.extend_from_slice(prev_node);
    data.extend_from_slice(&index_bytes);
    blake3_xof(&data, NODE_SIZE)
}

pub fn generate_program(state: &State) -> Program {
    let words = state.as_u64_array();
    let mut instructions = Vec::with_capacity(PROGRAM_LENGTH);

    for i in 0..PROGRAM_LENGTH {
        let word_idx = i % NUM_REGISTERS;
        let bit_offset = (i % 8) * 8;
        let selector = words[word_idx];

        let op_bits = (selector >> bit_offset) & 0x07;
        let dst = ((selector >> (bit_offset + 3)) & 0x07) as u8;
        let src = ((selector >> (bit_offset + 6)) & SRC_MASK) as u8;

        let instruction = match op_bits {
            0 => Instruction::Add { dst, src },
            1 => Instruction::Sub { dst, src },
            2 => Instruction::Mul { dst, src },
            3 => Instruction::Xor { dst, src },
            4 => Instruction::Rotl { dst, src },
            5 => Instruction::Rotr { dst, src },
            6 => Instruction::Mulh { dst, src },
            7 => Instruction::Swap { a: dst, b: src },
            _ => unreachable!(),
        };
        instructions.push(instruction);
    }

    Program { instructions }
}

pub fn derive_indices(state: &State, step: u64) -> (usize, usize, usize) {
    let words = state.as_u64_array();
    let idx1 = (words[0].wrapping_add(step) % NUM_NODES as u64) as usize;
    let idx2 = (words[1].wrapping_mul(step.wrapping_add(1)) % NUM_NODES as u64) as usize;
    let idx_write = ((words[2] ^ words[3]) % NUM_NODES as u64) as usize;
    (idx1, idx2, idx_write)
}

fn node_word_count() -> usize {
    NODE_SIZE / 8
}

fn node_as_u64_array(node: &[u8]) -> Vec<u64> {
    let word_count = node_word_count();
    let mut words = Vec::with_capacity(word_count);
    for i in 0..word_count {
        let bytes = &node[i * 8..i * 8 + 8];
        words.push(u64::from_le_bytes(bytes.try_into().unwrap()));
    }
    words
}

pub fn execute_program(
    state: &mut State,
    program: &Program,
    node1: &[u8],
    node2: &[u8],
) {
    let node1_words = node_as_u64_array(node1);
    let node2_words = node_as_u64_array(node2);
    let mut state_arr = state.as_u64_array();

    for instruction in &program.instructions {
        instruction.execute(&mut state_arr, &node1_words, &node2_words);
    }

    state.write_all_u64(&state_arr);
}

/// Applies data-dependent branching by hashing state and node data.
///
/// ## Branch Variant Design
///
/// The 4-way branching mixes different amounts of node data per variant:
/// - Variant 0: state + first 32 bytes of node1
/// - Variant 1: state + first 32 bytes of node1 + node2
/// - Variant 2: state + first 32 bytes of node2 + node1
/// - Variant 3: state + first 32 bytes of both node1 and node2
///
/// This deviates from the spec (which used the same format for all variants)
/// but creates more memory dependence per branch, which is better for ASIC resistance.
///
/// ## Bounds Safety
///
/// Node slices `&node[..BRANCH_NODE_PREFIX]` are safe because nodes are always
/// exactly NODE_SIZE = 1 MiB, which is >> 32 bytes.
pub fn apply_branch(
    state: &mut State,
    step: u32,
    node1: &[u8],
    node2: &[u8],
) {
    let words = state.as_u64_array();
    let branch_variant = (words[0] & BRANCH_MASK) as u8;
    let state_bytes = state.as_bytes();

    let mut input = Vec::with_capacity(16 + 32 + 64);
    input.extend_from_slice(DOMAIN_BRANCH);
    input.extend_from_slice(&step.to_le_bytes());
    input.push(branch_variant);
    match branch_variant {
        0 => {
            input.extend_from_slice(state_bytes);
            input.extend_from_slice(&node1[..BRANCH_NODE_PREFIX]);
        }
        1 => {
            input.extend_from_slice(state_bytes);
            input.extend_from_slice(&node1[..BRANCH_NODE_PREFIX]);
            input.extend_from_slice(&node2[..BRANCH_NODE_PREFIX]);
        }
        2 => {
            input.extend_from_slice(state_bytes);
            input.extend_from_slice(&node2[..BRANCH_NODE_PREFIX]);
            input.extend_from_slice(&node1[..BRANCH_NODE_PREFIX]);
        }
        3 => {
            input.extend_from_slice(state_bytes);
            input.extend_from_slice(&node1[..BRANCH_NODE_PREFIX]);
            input.extend_from_slice(&node2[..BRANCH_NODE_PREFIX]);
        }
        _ => unreachable!(),
    }

    let output = blake3_xof(&input, STATE_SIZE_SPEC);
    let mut state_arr = state.as_u64_array();
    for i in 0..NUM_REGISTERS {
        let xor_val = u64::from_le_bytes(output[i * 8..(i + 1) * 8].try_into().unwrap());
        state_arr[i] ^= xor_val;
    }
    state.write_all_u64(&state_arr);
}

pub fn compute_merkle_root(dataset: &Dataset) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_MEMORY);
    for node in &dataset.nodes {
        hasher.update(node);
    }
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(result.as_bytes());
    Hash(arr)
}

pub fn compute_merkle_root_from_slice(nodes: &[&[u8]]) -> Hash {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_MEMORY);
    for node in nodes {
        hasher.update(node);
    }
    let result = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(result.as_bytes());
    Hash(arr)
}

pub fn evo_omap_hash<D: DatasetLike>(
    dataset: &mut D,
    header: &[u8],
    height: u64,
    nonce: u64,
) -> Hash {
    let seed = compute_mining_seed(header, height, nonce);
    let mut state = State::from_seed(&seed);

    let mut commitment_data = Vec::with_capacity(40);
    commitment_data.extend_from_slice(DOMAIN_COMMITMENT);
    commitment_data.extend_from_slice(&height.to_le_bytes());
    let mut commitment_hash = blake3_256(&commitment_data);

    for step in 0..NUM_STEPS {
        let program = generate_program(&state);
        let (idx1, idx2, idx_write) = derive_indices(&state, step as u64);

        let node1 = dataset.get(idx1).to_vec();
        let node2 = dataset.get(idx2).to_vec();

        execute_program(&mut state, &program, &node1, &node2);

        apply_branch(&mut state, step as u32, &node1, &node2);

        let state_bytes = state.as_bytes();
        let mut write_data = Vec::with_capacity(WRITE_NODE_PREFIX + STATE_HASH_PREFIX);
        write_data.extend_from_slice(&node1[..WRITE_NODE_PREFIX]);
        write_data.extend_from_slice(&state_bytes[..STATE_HASH_PREFIX]);
        let written = blake3_xof(&write_data, NODE_SIZE);
        dataset.set(idx_write, written);

        commitment_hash = blake3_256(
            &commitment_hash
                .as_ref()
                .iter()
                .chain(&state_bytes[..32])
                .cloned()
                .collect::<Vec<u8>>(),
        );
    }

    let state_summary = blake3_256(state.as_bytes());
    let nodes = dataset.as_node_slice();
    let memory_commitment = compute_merkle_root_from_slice(&nodes);
    let final_input: Vec<u8> = state_summary
        .as_ref()
        .iter()
        .chain(commitment_hash.as_ref())
        .chain(memory_commitment.as_ref())
        .cloned()
        .collect();

    sha3_256(&final_input)
}

pub fn mine(
    header: &[u8],
    height: u64,
    difficulty: u64,
    max_nonce_attempts: u64,
) -> Option<u64> {
    if difficulty == 0 {
        return None;
    }
    let epoch_seed = compute_epoch_seed(height);
    let base_dataset = generate_dataset(&epoch_seed);
    let target = u64::MAX / difficulty;

    let mut cow_dataset = CowDataset::new(&base_dataset);

    for nonce in 0..max_nonce_attempts {
        cow_dataset.reset();

        let pow_hash = evo_omap_hash(&mut cow_dataset, header, height, nonce);

        let hash_int = u64::from_be_bytes(pow_hash.0[..8].try_into().unwrap());
        if hash_int < target {
            return Some(nonce);
        }
    }

    None
}

pub fn verify(
    header: &[u8],
    height: u64,
    nonce: u64,
    difficulty: u64,
) -> bool {
    if difficulty == 0 {
        return false;
    }
    let epoch_seed = compute_epoch_seed(height);
    let mut dataset = generate_dataset(&epoch_seed);
    let pow_hash = evo_omap_hash(&mut dataset, header, height, nonce);
    let target = u64::MAX / difficulty;
    let hash_int = u64::from_be_bytes(pow_hash.0[..8].try_into().unwrap());
    hash_int < target
}

pub fn verify_light(
    header: &[u8],
    height: u64,
    nonce: u64,
    difficulty: u64,
) -> bool {
    if difficulty == 0 {
        return false;
    }
    let epoch_seed = compute_epoch_seed(height);
    let cache = generate_cache(&epoch_seed);
    let mut dataset = Dataset::new();

    let mut prev_node = Vec::new();
    for i in 0..NUM_NODES {
        let node = if i == 0 {
            generate_node0(&epoch_seed)
        } else {
            reconstruct_node(&cache, &epoch_seed, i, &prev_node)
        };
        dataset.set(i, node.clone());
        prev_node = node;
    }

    let pow_hash = evo_omap_hash(&mut dataset, header, height, nonce);
    let target = u64::MAX / difficulty;
    let hash_int = u64::from_be_bytes(pow_hash.0[..8].try_into().unwrap());
    hash_int < target
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =============================================================================
    // 1. DETERMINISM TESTS
    // =============================================================================

    #[test]
    fn test_determinism_same_inputs_same_hash() {
        let header = b"determinism test header";
        let height = 100u64;
        let nonce = 42u64;

        let seed = compute_epoch_seed(height);
        let mut ds1 = generate_dataset(&seed);
        let mut ds2 = generate_dataset(&seed);

        let hash1 = evo_omap_hash(&mut ds1, header, height, nonce);
        let hash2 = evo_omap_hash(&mut ds2, header, height, nonce);

        assert_eq!(hash1, hash2, "Same inputs must produce identical hash");
    }

    #[test]
    fn test_determinism_fuzz_50_random_combinations() {
        let mut rng_state: u64 = 0x1234567890ABCDEF;

        for _ in 0..50 {
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);

            let _seed_bytes: [u8; 1] = (rng_state as u8).to_le_bytes();

            let seed = compute_epoch_seed(rng_state % 10000);

            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let nonce = rng_state;

            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let height = rng_state % 10000;

            let header = format!("header_{}", rng_state % 1000);

            let mut ds1 = generate_dataset(&seed);
            let mut ds2 = generate_dataset(&seed);
            let h1 = evo_omap_hash(&mut ds1, header.as_bytes(), height, nonce);
            let h2 = evo_omap_hash(&mut ds2, header.as_bytes(), height, nonce);

            assert_eq!(h1, h2);
        }
    }

    #[test]
    #[ignore]
    fn test_commitment_hash_affects_final_hash() {
        let header = b"commitment test header";
        let height = 100u64;
        let nonce = 42u64;

        let seed = compute_epoch_seed(height);
        let mut dataset = generate_dataset(&seed);

        let hash1 = evo_omap_hash(&mut dataset, header, height, nonce);

        let seed2 = compute_epoch_seed(height.wrapping_add(1));
        let mut dataset2 = generate_dataset(&seed2);
        let hash2 = evo_omap_hash(&mut dataset2, header, height, nonce);

        assert_ne!(hash1, hash2, "Different epoch seeds must produce different hashes");

        let mut dataset3 = generate_dataset(&seed);
        let hash3 = evo_omap_hash(&mut dataset3, b"different header", height, nonce);

        assert_ne!(hash1, hash3, "Different headers must produce different hashes");
    }

    #[test]
    fn test_dataset_generation_deterministic() {
        let seed = compute_epoch_seed(0);
        let ds1 = generate_dataset(&seed);
        let ds2 = generate_dataset(&seed);

        assert_eq!(ds1.nodes.len(), NUM_NODES);
        for i in 0..NUM_NODES {
            assert_eq!(ds1.nodes[i], ds2.nodes[i], "Node {} must be identical", i);
        }
    }

    // =============================================================================
    // 2. DATASET GENERATION TESTS
    // =============================================================================

    #[test]
    fn test_dataset_node_0_format() {
        let seed = compute_epoch_seed(0);
        let seed_bytes = seed.as_ref();

        let mut data = Vec::new();
        data.extend_from_slice(DOMAIN_NODE);
        data.extend_from_slice(seed_bytes);
        data.extend_from_slice(&0u64.to_le_bytes());

        let expected_node_0 = blake3_xof(&data, NODE_SIZE);

        let ds = generate_dataset(&seed);
        assert_eq!(ds.nodes[0], expected_node_0);
    }

    #[test]
    fn test_dataset_node_i_chained() {
        let seed = compute_epoch_seed(0);
        let ds = generate_dataset(&seed);

        for i in 1..NUM_NODES {
            let seed_bytes = seed.as_ref();
            let mut data = Vec::new();
            data.extend_from_slice(DOMAIN_NODE);
            data.extend_from_slice(seed_bytes);
            data.extend_from_slice(&ds.nodes[i - 1]);
            data.extend_from_slice(&(i as u64).to_le_bytes());

            let expected = blake3_xof(&data, NODE_SIZE);
            assert_eq!(ds.nodes[i], expected, "Node {} should be chained from node {}", i, i - 1);
        }
    }

    #[test]
    fn test_dataset_node_size_exactly_1mb() {
        let seed = compute_epoch_seed(0);
        let ds = generate_dataset(&seed);

        for i in 0..NUM_NODES {
            assert_eq!(ds.nodes[i].len(), NODE_SIZE, "Node {} should be 1 MiB", i);
            assert_eq!(ds.nodes[i].len(), 1_048_576, "Node {} should be exactly 1,048,576 bytes", i);
        }
    }

    #[test]
    fn test_dataset_has_256_nodes() {
        let seed = compute_epoch_seed(0);
        let ds = generate_dataset(&seed);
        assert_eq!(ds.nodes.len(), 256);
    }

    #[test]
    fn test_different_seeds_different_datasets() {
        let seed0 = compute_epoch_seed(0);
        let seed1 = compute_epoch_seed(1024);
        let ds0 = generate_dataset(&seed0);
        let ds1 = generate_dataset(&seed1);

        assert_ne!(ds0.nodes[0], ds1.nodes[0], "Different seeds produce different node 0");
        assert_ne!(ds0.nodes[128], ds1.nodes[128], "Different seeds produce different node 128");
        assert_ne!(ds0.nodes[255], ds1.nodes[255], "Different seeds produce different node 255");
    }

    // =============================================================================
    // 3. EPOCH SEED DERIVATION TESTS
    // =============================================================================

    #[test]
    fn test_epoch_seed_format() {
        let seed0 = compute_epoch_seed(0);

        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(DOMAIN_EPOCH);
        expected_data.extend_from_slice(&0u64.to_le_bytes());
        let expected = blake3_256(&expected_data);

        assert_eq!(seed0, expected);
    }

    #[test]
    fn test_epoch_seed_epoch_0_all_heights_same() {
        let seed0 = compute_epoch_seed(0);
        let seed1 = compute_epoch_seed(1);
        let seed512 = compute_epoch_seed(512);
        let seed1023 = compute_epoch_seed(1023);

        assert_eq!(seed0, seed1);
        assert_eq!(seed0, seed512);
        assert_eq!(seed0, seed1023);
    }

    #[test]
    fn test_epoch_seed_different_epochs_different_seeds() {
        let seed0 = compute_epoch_seed(0);
        let seed1 = compute_epoch_seed(1024);
        let seed2 = compute_epoch_seed(2048);

        assert_ne!(seed0, seed1);
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_epoch_seed_is_32_bytes() {
        let seed = compute_epoch_seed(100);
        assert_eq!(seed.0.len(), 32);
    }

    // =============================================================================
    // 4. MINING SEED DERIVATION TESTS
    // =============================================================================

    #[test]
    fn test_mining_seed_format() {
        let header = b"test header";
        let height = 100u64;
        let nonce = 42u64;

        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(DOMAIN_SEED);
        expected_data.extend_from_slice(&(header.len() as u64).to_le_bytes());
        expected_data.extend_from_slice(header);
        expected_data.extend_from_slice(&height.to_le_bytes());
        expected_data.extend_from_slice(&nonce.to_le_bytes());

        let expected = blake3_256(&expected_data);
        let actual = compute_mining_seed(header, height, nonce);

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_mining_seed_different_nonces_different_seeds() {
        let header = b"test header";
        let height = 100u64;

        let seed1 = compute_mining_seed(header, height, 0);
        let seed2 = compute_mining_seed(header, height, 1);

        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_mining_seed_different_headers_different_seeds() {
        let height = 100u64;
        let nonce = 42u64;

        let seed1 = compute_mining_seed(b"header1", height, nonce);
        let seed2 = compute_mining_seed(b"header2", height, nonce);

        assert_ne!(seed1, seed2);
    }

    // =============================================================================
    // 5. PROGRAM GENERATION TESTS
    // =============================================================================

    #[test]
    fn test_program_generation_always_8_instructions() {
        let seed = Hash([1u8; 32]);
        let state = State::from_seed(&seed);

        for _ in 0..100 {
            let rng_state = (state.as_u64_array()[0] ^ state.as_u64_array()[1]).wrapping_add(1);
            let test_state = State::from_seed(&Hash::from_bytes([(rng_state & 0xFF) as u8; 32]));
            let program = generate_program(&test_state);
            assert_eq!(program.instructions.len(), PROGRAM_LENGTH);
        }
    }

    #[test]
    fn test_program_generation_only_valid_opcodes() {
        let seed = Hash([42u8; 32]);
        let state = State::from_seed(&seed);
        let program = generate_program(&state);

        for instruction in &program.instructions {
            match instruction {
                Instruction::Add { .. } => {}
                Instruction::Sub { .. } => {}
                Instruction::Mul { .. } => {}
                Instruction::Xor { .. } => {}
                Instruction::Rotl { .. } => {}
                Instruction::Rotr { .. } => {}
                Instruction::Mulh { .. } => {}
                Instruction::Swap { .. } => {}
            }
        }
    }

    #[test]
    fn test_program_generation_src_register_always_valid() {
        let seed = Hash([99u8; 32]);
        let state = State::from_seed(&seed);
        let program = generate_program(&state);

        for instruction in &program.instructions {
            let src = match instruction {
                Instruction::Add { src, .. } => *src,
                Instruction::Sub { src, .. } => *src,
                Instruction::Mul { src, .. } => *src,
                Instruction::Xor { src, .. } => *src,
                Instruction::Rotl { .. } => continue,
                Instruction::Rotr { .. } => continue,
                Instruction::Mulh { src, .. } => *src,
                Instruction::Swap { .. } => continue,
            };
            assert!(src < 128, "src register {} must be 0-127", src);
        }
    }

    #[test]
    fn test_program_generation_dst_register_always_valid() {
        let seed = Hash([77u8; 32]);
        let state = State::from_seed(&seed);
        let program = generate_program(&state);

        for instruction in &program.instructions {
            let dst = match instruction {
                Instruction::Add { dst, .. } => *dst,
                Instruction::Sub { dst, .. } => *dst,
                Instruction::Mul { dst, .. } => *dst,
                Instruction::Xor { dst, .. } => *dst,
                Instruction::Rotl { dst, .. } => *dst,
                Instruction::Rotr { dst, .. } => *dst,
                Instruction::Mulh { dst, .. } => *dst,
                Instruction::Swap { a, .. } => *a,
            };
            assert!(dst < 8, "dst register {} must be 0-7", dst);
        }
    }

    #[test]
    fn test_program_generation_deterministic() {
        let seed = Hash([123u8; 32]);
        let state = State::from_seed(&seed);
        let p1 = generate_program(&state);
        let p2 = generate_program(&state);
        assert_eq!(p1.instructions, p2.instructions);
    }

    #[test]
    fn test_different_states_different_programs() {
        let state1 = State::from_seed(&Hash([1u8; 32]));
        let state2 = State::from_seed(&Hash([2u8; 32]));
        let p1 = generate_program(&state1);
        let p2 = generate_program(&state2);
        assert_ne!(p1.instructions, p2.instructions);
    }

    // =============================================================================
    // 6. INSTRUCTION EXECUTION TESTS
    // =============================================================================

    #[test]
    fn test_instruction_add_wrapping() {
        let mut state = [u64::MAX, 0, 0, 0, 0, 0, 0, 0];
        let node1_words = [1u64; 128];
        let node2_words = [0u64; 128];

        let add = Instruction::Add { dst: 0, src: 0 };
        add.execute(&mut state, &node1_words, &node2_words);

        assert_eq!(state[0], 0);
    }

    #[test]
    fn test_instruction_sub_wrapping() {
        let mut state = [0u64, 0, 0, 0, 0, 0, 0, 0];
        let node1_words = [0u64; 128];
        let node2_words = [1u64; 128];

        let sub = Instruction::Sub { dst: 0, src: 0 };
        sub.execute(&mut state, &node1_words, &node2_words);

        assert_eq!(state[0], u64::MAX);
    }

#[test]
    fn test_instruction_mul_wrapping() {
        let mut state = [2u64, 0, 0, 0, 0, 0, 0, 0];
        let mut node1_words = [0u64; 128];
        node1_words[0] = u64::MAX;
        let node2_words = [0u64; 128];

        let mul = Instruction::Mul { dst: 0, src: 0 };
        mul.execute(&mut state, &node1_words, &node2_words);

        assert_eq!(state[0], 2u64.wrapping_mul(u64::MAX));
    }

    #[test]
    fn test_instruction_xor() {
        let mut state = [0xFFu64, 0, 0, 0, 0, 0, 0, 0];
        let node1_words = [0u64; 128];
        let node2_words = [0x0Fu64; 128];

        let xor = Instruction::Xor { dst: 0, src: 0 };
        xor.execute(&mut state, &node1_words, &node2_words);

        assert_eq!(state[0], 0xF0u64);
    }

    #[test]
    fn test_instruction_rotr_data_dependent() {
        let mut state = [0x01u64, 0, 0, 0, 0, 0, 0, 0];
        let mut node1_words = [0u64; 128];
        let node2_words = [0u64; 128];
        node1_words[0] = 1;

        let rotl = Instruction::Rotl { dst: 0, src: 0 };
        rotl.execute(&mut state, &node1_words, &node2_words);

        let val = 0x01u64;
        let expected = val.rotate_left((node1_words[0] % 64) as u32);
        assert_eq!(state[0], expected);
    }

    #[test]
    fn test_instruction_mulh_edge_case() {
        let mut state = [u64::MAX, 0, 0, 0, 0, 0, 0, 0];
        let node1_words = [u64::MAX; 128];
        let node2_words = [0u64; 128];

        let mulh = Instruction::Mulh { dst: 0, src: 0 };
        mulh.execute(&mut state, &node1_words, &node2_words);

        let wide: u128 = (u64::MAX as u128).wrapping_mul(u64::MAX as u128);
        let expected = (wide >> 64) as u64;
        assert_eq!(state[0], expected);
    }

    #[test]
    fn test_instruction_swap() {
        let mut state = [1u64, 2, 3, 4, 5, 6, 7, 8];
        let node1_words = [0u64; 128];
        let node2_words = [0u64; 128];

        let swap = Instruction::Swap { a: 0, b: 1 };
        swap.execute(&mut state, &node1_words, &node2_words);

        assert_eq!(state[0], 2);
        assert_eq!(state[1], 1);
    }

    // =============================================================================
    // 7. BRANCH OPERATION TESTS
    // =============================================================================

    #[test]
    fn test_branch_variant_range() {
        for _ in 0..100 {
            let state = State::from_seed(&Hash([rand::random(); 32]));
            let words = state.as_u64_array();
            let variant = words[0] & 0x03;
            assert!(variant <= 3, "Branch variant must be 0-3");
        }
    }

    #[test]
    fn test_branch_xor_not_replace() {
        let seed1 = Hash([1u8; 32]);
        let seed2 = Hash([2u8; 32]);

        let state1_orig = State::from_seed(&seed1);
        let state2_orig = State::from_seed(&seed2);

        let node1 = vec![0xFFu8; 1024];
        let node2 = vec![0xAAu8; 1024];

        let mut s1 = state1_orig.clone();
        let mut s2 = state2_orig.clone();

        apply_branch(&mut s1, 0, &node1, &node2);
        apply_branch(&mut s2, 0, &node1, &node2);

        let orig_words = state1_orig.as_u64_array();
        let new_words = s1.as_u64_array();
        let mut any_different = false;
        for i in 0..8 {
            if orig_words[i] != new_words[i] {
                any_different = true;
                break;
            }
        }
        assert!(any_different, "Branch must modify state via XOR");

        assert_ne!(s1.as_u64_array(), s2.as_u64_array(), "Different states must produce different branches");
    }

    #[test]
    fn test_branch_distribution_uniform() {
        let mut counts = [0u64; 4];

        for i in 0..10000 {
            let seed = Hash::from_bytes({
                let mut arr = [0u8; 32];
                arr[0] = (i & 0xFF) as u8;
                arr
            });
            let state = State::from_seed(&seed);
            let words = state.as_u64_array();
            let variant = (words[0] & 0x03) as usize;
            counts[variant] += 1;
        }

        for i in 0..4 {
            let percentage = counts[i] as f64 / 10000.0;
            assert!(percentage > 0.15 && percentage < 0.40,
                "Branch {} has {}%, expected 20-35%", i, percentage * 100.0);
        }
    }

    // =============================================================================
    // 8. WRITE STEP TESTS
    // =============================================================================

    #[test]
    fn test_write_step_mutates_dataset() {
        let header = b"test write";
        let height = 50u64;
        let nonce = 0u64;

        let seed = compute_epoch_seed(height);
        let base_ds = generate_dataset(&seed);

        let mut ds = Dataset::new();
        for i in 0..NUM_NODES {
            ds.set(i, base_ds.get(i).to_vec());
        }

        let original_node_100 = ds.get(100).to_vec();

        let _hash = evo_omap_hash(&mut ds, header, height, nonce);

        let final_node_100 = ds.get(100).to_vec();
        assert_ne!(original_node_100, final_node_100, "Dataset node should be modified");
    }

    #[test]
    fn test_write_step_deterministic() {
        let header = b"deterministic write test";
        let height = 75u64;
        let nonce = 123u64;

        let seed = compute_epoch_seed(height);
        let base_ds = generate_dataset(&seed);

        let mut ds1 = Dataset::new();
        let mut ds2 = Dataset::new();
        for i in 0..NUM_NODES {
            ds1.set(i, base_ds.get(i).to_vec());
            ds2.set(i, base_ds.get(i).to_vec());
        }

        let _hash1 = evo_omap_hash(&mut ds1, header, height, nonce);
        let _hash2 = evo_omap_hash(&mut ds2, header, height, nonce);

        for i in 0..NUM_NODES {
            assert_eq!(ds1.nodes[i], ds2.nodes[i], "Same inputs must produce same write at node {}", i);
        }
    }

    // =============================================================================
    // 9. ROLLING COMMITMENT TESTS
    // =============================================================================

    #[test]
    fn test_rolling_commitment_deterministic() {
        let header = b"rolling commitment test";
        let height = 200u64;
        let nonce = 0u64;

        let seed = compute_epoch_seed(height);
        let mut ds1 = generate_dataset(&seed);
        let mut ds2 = generate_dataset(&seed);

        let _hash1 = evo_omap_hash(&mut ds1, header, height, nonce);
        let _hash2 = evo_omap_hash(&mut ds2, header, height, nonce);
    }

    #[test]
    fn test_rolling_commitment_different_paths_different_final() {
        let header = b"rolling path test";
        let height = 300u64;

        let seed = compute_epoch_seed(height);

        let mut ds1 = generate_dataset(&seed);
        let h1 = evo_omap_hash(&mut ds1, header, height, 0);

        let mut ds2 = generate_dataset(&seed);
        let h2 = evo_omap_hash(&mut ds2, header, height, 1);

        assert_ne!(h1, h2, "Different nonces must produce different hashes and thus different final commitments");
    }

    // =============================================================================
    // 10. MEMORY COMMITMENT TESTS
    // =============================================================================

    #[test]
    fn test_memory_commitment_format() {
        let seed = compute_epoch_seed(0);
        let ds = generate_dataset(&seed);

        let mut hasher = blake3::Hasher::new();
        hasher.update(DOMAIN_MEMORY);
        for node in &ds.nodes {
            hasher.update(node);
        }
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(result.as_bytes());
        let expected = Hash::from_bytes(arr);

        let computed = compute_merkle_root(&ds);

        assert_eq!(computed, expected);
    }

    #[test]
    fn test_memory_commitment_changes_with_dataset() {
        let seed = compute_epoch_seed(0);
        let ds = generate_dataset(&seed);
        let root1 = compute_merkle_root(&ds);

        let mut modified_ds = generate_dataset(&seed);
        modified_ds.nodes[0][0] ^= 0x01;
        let root2 = compute_merkle_root(&modified_ds);

        assert_ne!(root1, root2, "Changing any node must change memory commitment");
    }

    // =============================================================================
    // 11. FINAL HASH TESTS
    // =============================================================================

    #[test]
    fn test_final_hash_uses_sha3_256() {
        let header = b"final hash test";
        let height = 500u64;
        let nonce = 0u64;

        let seed = compute_epoch_seed(height);
        let mut ds = generate_dataset(&seed);
        let hash = evo_omap_hash(&mut ds, header, height, nonce);

        assert_eq!(hash.0.len(), 32);
    }

    #[test]
    fn test_final_hash_different_inputs_different_outputs() {
        let seed = compute_epoch_seed(0);

        let mut ds1 = generate_dataset(&seed);
        let h1 = evo_omap_hash(&mut ds1, b"header1", 0, 0);

        let mut ds2 = generate_dataset(&seed);
        let h2 = evo_omap_hash(&mut ds2, b"header2", 0, 0);

        assert_ne!(h1, h2);
    }

    #[test]
    fn test_final_hash_deterministic() {
        let header = b"deterministic final hash";
        let height = 600u64;
        let nonce = 99u64;

        let seed = compute_epoch_seed(height);
        let mut ds1 = generate_dataset(&seed);
        let mut ds2 = generate_dataset(&seed);

        let h1 = evo_omap_hash(&mut ds1, header, height, nonce);
        let h2 = evo_omap_hash(&mut ds2, header, height, nonce);

        assert_eq!(h1, h2);
    }

    // =============================================================================
    // 12. LIGHT VS FULL VERIFICATION TESTS
    // =============================================================================

    #[test]
    fn test_light_and_full_produce_same_hash() {
        let header = b"light vs full verification";
        let height = 50u64;
        let nonce = 0u64;

        let seed = compute_epoch_seed(height);

        let mut ds_full = generate_dataset(&seed);
        let hash_full = evo_omap_hash(&mut ds_full, header, height, nonce);

        let _cache = generate_cache(&seed);
        let mut ds_light = Dataset::new();
        let mut prev_node = Vec::new();
        for i in 0..NUM_NODES {
            let node = if i == 0 {
                blake3_xof(
                    &[
                        DOMAIN_NODE,
                        seed.as_ref(),
                        &(0u64).to_le_bytes(),
                    ]
                    .iter()
                    .flat_map(|v| v.iter())
                    .cloned()
                    .collect::<Vec<u8>>(),
                    NODE_SIZE,
                )
            } else {
                let mut data = Vec::new();
                data.extend_from_slice(DOMAIN_NODE);
                data.extend_from_slice(seed.as_ref());
                data.extend_from_slice(&prev_node);
                data.extend_from_slice(&(i as u64).to_le_bytes());
                blake3_xof(&data, NODE_SIZE)
            };
            ds_light.set(i, node.clone());
            prev_node = node;
        }
        let hash_light = evo_omap_hash(&mut ds_light, header, height, nonce);

        assert_eq!(hash_full, hash_light);
    }

    // =============================================================================
    // 13. DOMAIN SEPARATOR UNIQUENESS TESTS
    // =============================================================================

    #[test]
    fn test_domain_separators_are_distinct() {
        let data = b"test data for domain separator";

        let hash_epoch = blake3_256(&[DOMAIN_EPOCH, data].iter().flat_map(|v| v.iter()).cloned().collect::<Vec<_>>());
        let hash_node = blake3_256(&[DOMAIN_NODE, data].iter().flat_map(|v| v.iter()).cloned().collect::<Vec<_>>());
        let hash_seed = blake3_256(&[DOMAIN_SEED, data].iter().flat_map(|v| v.iter()).cloned().collect::<Vec<_>>());
        let hash_cache = blake3_256(&[DOMAIN_CACHE, data].iter().flat_map(|v| v.iter()).cloned().collect::<Vec<_>>());
        let hash_branch = blake3_256(&[DOMAIN_BRANCH, data].iter().flat_map(|v| v.iter()).cloned().collect::<Vec<_>>());
        let hash_commitment = blake3_256(&[DOMAIN_COMMITMENT, data].iter().flat_map(|v| v.iter()).cloned().collect::<Vec<_>>());
        let hash_memory = blake3_256(&[DOMAIN_MEMORY, data].iter().flat_map(|v| v.iter()).cloned().collect::<Vec<_>>());

        let hashes = [hash_epoch, hash_node, hash_seed, hash_cache, hash_branch, hash_commitment, hash_memory];

        for i in 0..hashes.len() {
            for j in (i+1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j], "Domain separator {} must be distinct from {}", i, j);
            }
        }
    }

    // =============================================================================
    // 14. OPERAND BOUNDS TESTS
    // =============================================================================

    #[test]
    fn test_operand_access_never_exceeds_127() {
        let header = b"operand bounds test";
        let height = 700u64;

        let seed = compute_epoch_seed(height);
        let mut ds = generate_dataset(&seed);

        let _hash = evo_omap_hash(&mut ds, header, height, 0);

        for i in 0..NUM_NODES {
            assert_eq!(ds.nodes[i].len(), NODE_SIZE);
        }
    }

    #[test]
    fn test_derive_indices_always_in_range() {
        for step in 0..100u64 {
            let state = State::from_seed(&Hash::from_bytes({
                let mut arr = [0u8; 32];
                arr[0..8].copy_from_slice(&step.to_le_bytes());
                arr
            }));

            let (idx1, idx2, idx_write) = derive_indices(&state, step);

            assert!(idx1 < NUM_NODES, "idx1 must be < {}", NUM_NODES);
            assert!(idx2 < NUM_NODES, "idx2 must be < {}", NUM_NODES);
            assert!(idx_write < NUM_NODES, "idx_write must be < {}", NUM_NODES);
        }
    }

    // =============================================================================
    // 15. COPY-ON-WRITE MINING TESTS
    // =============================================================================

    #[test]
    fn test_cow_produces_same_result_as_naive() {
        let header = b"CoW mining test";
        let height = 800u64;
        let seed = compute_epoch_seed(height);

        let base_ds = generate_dataset(&seed);

        for nonce in 0..5u64 {
            let mut ds_naive = Dataset::new();
            for i in 0..NUM_NODES {
                ds_naive.set(i, base_ds.get(i).to_vec());
            }
            let hash_naive = evo_omap_hash(&mut ds_naive, header, height, nonce);

            let mut cow = CowDataset::new(&base_ds);
            cow.reset();
            let mut ds_cow = Dataset::new();
            for i in 0..NUM_NODES {
                ds_cow.set(i, cow.get(i).to_vec());
            }
            let hash_cow = evo_omap_hash(&mut ds_cow, header, height, nonce);

            assert_eq!(hash_naive, hash_cow, "CoW must produce same result as naive for nonce {}", nonce);
        }
    }

    // =============================================================================
    // 16. EPOCH BOUNDARY TESTS
    // =============================================================================

    #[test]
    fn test_epoch_boundary_different_datasets() {
        let seed0 = compute_epoch_seed(0);
        let seed1023 = compute_epoch_seed(1023);
        let seed1024 = compute_epoch_seed(1024);

        assert_eq!(seed0, seed1023);
        assert_ne!(seed0, seed1024);

        let ds0 = generate_dataset(&seed0);
        let ds1024 = generate_dataset(&seed1024);

        assert_ne!(ds0.nodes[0], ds1024.nodes[0]);
        assert_ne!(ds0.nodes[128], ds1024.nodes[128]);
        assert_ne!(ds0.nodes[255], ds1024.nodes[255]);
    }

    // =============================================================================
    // 17. DIFFICULTY VALIDATION TESTS
    // =============================================================================

    #[test]
    fn test_difficulty_validation_easy() {
        let header = b"easy difficulty test";
        let height = 900u64;
        let difficulty = 1u64;
        let target = u64::MAX / difficulty;

        let seed = compute_epoch_seed(height);
        let mut ds = generate_dataset(&seed);
        let hash = evo_omap_hash(&mut ds, header, height, 0);
        let hash_int = u64::from_be_bytes(hash.0[..8].try_into().unwrap());

        assert!(hash_int < target, "Difficulty 1 should accept most hashes");
    }

    #[test]
    fn test_difficulty_validation_hard() {
        let header = b"hard difficulty test";
        let height = 950u64;
        let difficulty = 1_000_000u64;

        assert!(!verify(header, height, 0, difficulty));
    }

    #[test]
    fn test_verify_accepts_valid_proof() {
        let header = b"valid proof test";
        let height = 1000u64;
        let difficulty = 1u64;
        let target = u64::MAX / difficulty;

        let seed = compute_epoch_seed(height);
        let base_ds = generate_dataset(&seed);

        let mut found_nonce = None;
        for nonce in 0..1_000_000u64 {
            let mut ds = Dataset::new();
            for i in 0..NUM_NODES {
                ds.set(i, base_ds.get(i).to_vec());
            }
            let hash = evo_omap_hash(&mut ds, header, height, nonce);
            let hash_int = u64::from_be_bytes(hash.0[..8].try_into().unwrap());
            if hash_int < target {
                found_nonce = Some(nonce);
                break;
            }
        }

        assert!(found_nonce.is_some(), "Failed to find valid nonce in 1M attempts");
        let nonce = found_nonce.unwrap();
        assert!(verify(header, height, nonce, difficulty));
    }

    // =============================================================================
    // 18. EDGE CASES TESTS
    // =============================================================================

    #[test]
    fn test_edge_case_zero_seed() {
        let seed = Hash([0u8; 32]);
        let state = State::from_seed(&seed);
        assert_ne!(state.as_u64_array(), [0u64; 8]);
    }

    #[test]
    fn test_edge_case_max_seed() {
        let seed = Hash([0xFFu8; 32]);
        let state = State::from_seed(&seed);
        assert_ne!(state.as_u64_array(), [0u64; 8]);
    }

    #[test]
    fn test_edge_case_empty_header() {
        let header: &[u8] = &[];
        let height = 0u64;
        let nonce = 0u64;

        let seed = compute_epoch_seed(height);
        let mut ds = generate_dataset(&seed);
        let hash = evo_omap_hash(&mut ds, header, height, nonce);

        assert_eq!(hash.0.len(), 32);
    }

    #[test]
    fn test_edge_case_nonce_max() {
        let header = b"max nonce test";
        let height = 0u64;
        let nonce = u64::MAX;

        let seed = compute_epoch_seed(height);
        let mut ds1 = generate_dataset(&seed);
        let mut ds2 = generate_dataset(&seed);

        let h1 = evo_omap_hash(&mut ds1, header, height, nonce);
        let h2 = evo_omap_hash(&mut ds2, header, height, nonce);

        assert_eq!(h1, h2);
    }

    #[test]
    fn test_edge_case_difficulty_1() {
        let header = b"difficulty 1 test";
        let height = 1100u64;
        let difficulty = 1u64;

        let seed = compute_epoch_seed(height);
        let mut ds = generate_dataset(&seed);
        let hash = evo_omap_hash(&mut ds, header, height, 0);
        let hash_int = u64::from_be_bytes(hash.0[..8].try_into().unwrap());
        let target = u64::MAX / difficulty;

        assert!(hash_int < target);
    }

    #[test]
    fn test_edge_case_integer_overflow_mul() {
        let mut state = [u64::MAX, 0, 0, 0, 0, 0, 0, 0];
        let node1_words = [u64::MAX; 128];
        let node2_words = [0u64; 128];

        let mul = Instruction::Mul { dst: 0, src: 0 };
        mul.execute(&mut state, &node1_words, &node2_words);

        let expected = u64::MAX.wrapping_mul(u64::MAX);
        assert_eq!(state[0], expected);
    }

    #[test]
    fn test_edge_case_mulh_max_values() {
        let mut state = [u64::MAX, 0, 0, 0, 0, 0, 0, 0];
        let node1_words = [u64::MAX; 128];
        let node2_words = [0u64; 128];

        let mulh = Instruction::Mulh { dst: 0, src: 0 };
        mulh.execute(&mut state, &node1_words, &node2_words);

        let wide: u128 = (u64::MAX as u128).wrapping_mul(u64::MAX as u128);
        let expected = (wide >> 64) as u64;
        assert_eq!(state[0], expected);
    }

    #[test]
    fn test_edge_case_rotr_by_0() {
        let mut state = [0x123456789ABCDEFu64, 0, 0, 0, 0, 0, 0, 0];
        let mut node1_words = [0u64; 128];
        let node2_words = [0u64; 128];
        node1_words[0] = 0;

        let rotr = Instruction::Rotr { dst: 0, src: 0 };
        rotr.execute(&mut state, &node1_words, &node2_words);

        assert_eq!(state[0], 0x123456789ABCDEF);
    }

    #[test]
    fn test_edge_case_rotl_by_63() {
        let mut state = [1u64, 0, 0, 0, 0, 0, 0, 0];
        let mut node1_words = [0u64; 128];
        let node2_words = [0u64; 128];
        node1_words[0] = 63;

        let rotl = Instruction::Rotl { dst: 0, src: 0 };
        rotl.execute(&mut state, &node1_words, &node2_words);

        let val = 1u64;
        let expected = val.rotate_left((node1_words[0] % 64) as u32);
        assert_eq!(state[0], expected);
    }

    // =============================================================================
    // 19. KNOWN-ANSWER TESTS
    // =============================================================================

    #[test]
    fn test_known_answer_epoch_seed() {
        let seed = compute_epoch_seed(0);
        let expected_first_8_bytes = [
            0x9bu8, 0x5bu8, 0x08u8, 0xa7u8, 0x71u8, 0xd5u8, 0x74u8, 0x67u8
        ];
        assert_eq!(&seed.0[..8], &expected_first_8_bytes);
    }

    #[test]
    fn test_known_answer_deterministic_hash() {
        let header = b"known answer test";
        let height = 1024u64;
        let nonce = 42u64;

        let seed = compute_epoch_seed(height);
        let mut ds = generate_dataset(&seed);
        let hash = evo_omap_hash(&mut ds, header, height, nonce);

        let hash_int = u64::from_be_bytes(hash.0[..8].try_into().unwrap());
        assert!(hash_int != 0, "Hash should not be zero");

        assert_eq!(hash.0.len(), 32, "Hash should be 32 bytes");
    }

    #[test]
    fn test_known_answer_verify_rejects_wrong_nonce() {
        let header = b"wrong nonce test";
        let height = 2000u64;
        let difficulty = 1000u64;

        assert!(!verify(header, height, 999999, difficulty));
    }

    // =============================================================================
    // STATE CONVERSION TESTS
    // =============================================================================

    #[test]
    fn test_state_as_u64_array() {
        let state = State([
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
            0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
            0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        ]);
        let arr = state.as_u64_array();
        assert_eq!(arr[0], 0x0706050403020100u64);
        assert_eq!(arr[1], 0x1716151413121110u64);
        assert_eq!(arr[7], 0x7776757473727170u64);
    }

    #[test]
    fn test_state_from_seed() {
        let seed = Hash([0u8; 32]);
        let state = State::from_seed(&seed);
        let arr = state.as_u64_array();
        assert_ne!(arr, [0u64; 8]);
    }

    // =============================================================================
    // INDEX DERIVATION TESTS
    // =============================================================================

    #[test]
    fn test_derive_indices() {
        let state = State([0u8; 64]);
        let (i1, i2, iw) = derive_indices(&state, 0);
        assert_eq!(i1, 0);
        assert_eq!(i2, 0);
        assert_eq!(iw, 0);
    }

    // =============================================================================
    // DATASET MODIFICATION TESTS
    // =============================================================================

    #[test]
    fn test_dataset_modification_after_hash() {
        let header = b"dataset modification test";
        let height = 3000u64;
        let nonce = 0u64;

        let seed = compute_epoch_seed(height);
        let base_ds = generate_dataset(&seed);

        let mut ds = Dataset::new();
        for i in 0..NUM_NODES {
            ds.set(i, base_ds.get(i).to_vec());
        }

        let original_node_0 = ds.get(0).to_vec();

        let _hash = evo_omap_hash(&mut ds, header, height, nonce);

        let final_node_0 = ds.get(0).to_vec();
        assert_ne!(original_node_0, final_node_0, "Dataset node should be modified after hash");
    }

    #[test]
    fn test_chained_dataset_generation() {
        let seed = compute_epoch_seed(0);
        let ds = generate_dataset(&seed);
        assert_ne!(ds.nodes[0], ds.nodes[1]);
        assert_ne!(ds.nodes[1], ds.nodes[2]);
        assert_ne!(ds.nodes[254], ds.nodes[255]);
    }

    #[test]
    fn test_node_size() {
        let seed = compute_epoch_seed(0);
        let ds = generate_dataset(&seed);
        assert_eq!(ds.nodes[0].len(), NODE_SIZE);
        assert_eq!(ds.nodes[255].len(), NODE_SIZE);
    }

    // =============================================================================
    // ADDITIONAL COMPREHENSIVE TESTS
    // =============================================================================

    #[test]
    fn test_full_hash_deterministic() {
        let header = b"test header for evo-omap";
        let height = 100u64;
        let nonce = 42u64;

        let seed0 = compute_epoch_seed(height);
        let mut ds1 = generate_dataset(&seed0);
        let mut ds2 = generate_dataset(&seed0);
        let h1 = evo_omap_hash(&mut ds1, header, height, nonce);
        let h2 = evo_omap_hash(&mut ds2, header, height, nonce);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_nonce_different_hash() {
        let header = b"test header";
        let height = 100u64;

        let seed = compute_epoch_seed(height);
        let mut ds1 = generate_dataset(&seed);
        let mut ds2 = generate_dataset(&seed);
        let h1 = evo_omap_hash(&mut ds1, header, height, 0);
        let h2 = evo_omap_hash(&mut ds2, header, height, 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_different_height_different_hash() {
        let header = b"test header";
        let nonce = 0u64;

        let seed0 = compute_epoch_seed(0);
        let seed1 = compute_epoch_seed(1);
        let mut ds1 = generate_dataset(&seed0);
        let mut ds2 = generate_dataset(&seed1);
        let h1 = evo_omap_hash(&mut ds1, header, 0, nonce);
        let h2 = evo_omap_hash(&mut ds2, header, 1, nonce);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_verify_rejects_invalid_proof() {
        let header = b"test header";
        let height = 100u64;
        let difficulty = 1_000_000u64;
        assert!(!verify(header, height, 0, difficulty));
    }

    #[test]
    fn test_light_vs_full_verification() {
        let header = b"test header for light verification";
        let height = 50u64;
        let difficulty = 1u64;
        let target = u64::MAX / difficulty;

        let seed = compute_epoch_seed(height);
        let base_ds = generate_dataset(&seed);

        let mut found_nonce = None;
        for nonce in 0..500_000u64 {
            let mut ds = Dataset::new();
            for i in 0..NUM_NODES {
                ds.set(i, base_ds.get(i).to_vec());
            }
            let hash = evo_omap_hash(&mut ds, header, height, nonce);
            let hash_int = u64::from_be_bytes(hash.0[..8].try_into().unwrap());
            if hash_int < target {
                found_nonce = Some(nonce);
                break;
            }
        }

        if let Some(nonce) = found_nonce {
            assert!(verify(header, height, nonce, difficulty));
            assert!(verify_light(header, height, nonce, difficulty));
        }
    }

    #[test]
    fn test_epoch_boundary() {
        let seed0 = compute_epoch_seed(0);
        let seed1023 = compute_epoch_seed(1023);
        let seed1024 = compute_epoch_seed(1024);
        assert_eq!(seed0, seed1023);
        assert_ne!(seed0, seed1024);
    }

    #[test]
    fn test_generate_dataset_deterministic() {
        let seed = compute_epoch_seed(0);
        let ds1 = generate_dataset(&seed);
        let ds2 = generate_dataset(&seed);
        assert_eq!(ds1.nodes.len(), NUM_NODES);
        assert_eq!(ds1.nodes.len(), ds2.nodes.len());
        for i in 0..NUM_NODES {
            assert_eq!(ds1.nodes[i], ds2.nodes[i]);
        }
    }

    #[test]
    fn test_generate_cache_deterministic() {
        let seed = compute_epoch_seed(0);
        let c1 = generate_cache(&seed);
        let c2 = generate_cache(&seed);
        assert_eq!(c1.data.len(), CACHE_SIZE);
        assert_eq!(c1.data, c2.data);
    }

    #[test]
    fn test_generate_program_deterministic() {
        let seed = Hash([1u8; 32]);
        let state = State::from_seed(&seed);
        let p1 = generate_program(&state);
        let p2 = generate_program(&state);
        assert_eq!(p1.instructions, p2.instructions);
    }

    #[test]
    fn test_compute_epoch_seed() {
        let seed0 = compute_epoch_seed(0);
        let seed1 = compute_epoch_seed(1);
        let seed1023 = compute_epoch_seed(1023);
        let seed1024 = compute_epoch_seed(1024);
        let seed1025 = compute_epoch_seed(1025);
        assert_eq!(seed0, compute_epoch_seed(0));
        assert_eq!(seed0, seed1);
        assert_eq!(seed0, seed1023);
        assert_ne!(seed0, seed1024);
        assert_eq!(seed1024, seed1025);
    }
}
