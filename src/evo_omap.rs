//! EVO-OMAP Proof-of-Work Algorithm Implementation
//!
//! This module implements the EVO-OMAP algorithm using parameters from
//! private_tuning.rs. The public specification is in public_spec.rs.

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

use crate::private_tuning::constants::*;

pub use crate::public_spec::DatasetSpec;
pub use crate::public_spec::CacheSpec;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct State(pub [u8; STATE_SIZE]);

impl State {
    pub fn as_u64_array(&self) -> [u64; 8] {
        let mut arr = [0u64; 8];
        for i in 0..8 {
            arr[i] = u64::from_be_bytes([
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

    pub fn as_u64_mut_array(&mut self) -> &mut [u64; 8] {
        let words_ptr = self.0.as_mut_ptr() as *mut u64;
        unsafe { std::slice::from_raw_parts_mut(words_ptr, 8) }
            .try_into()
            .unwrap()
    }

    pub fn as_bytes(&self) -> &[u8; STATE_SIZE] {
        &self.0
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8; STATE_SIZE] {
        &mut self.0
    }

    pub fn from_seed(seed: &Hash) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed.as_ref());
        let mut reader = hasher.finalize_xof();
        let mut output = [0u8; STATE_SIZE];
        reader.fill(&mut output);
        State(output)
    }
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
}

impl<'a> CowDataset<'a> {
    pub fn new(base: &'a Dataset) -> Self {
        Self {
            base,
            modified: vec![None; NUM_NODES],
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
        self.modified[index] = Some(node);
    }

    pub fn reset(&mut self) {
        for i in 0..NUM_NODES {
            self.modified[i] = None;
        }
    }

    pub fn as_dataset(&self) -> Vec<&[u8]> {
        let mut result = Vec::with_capacity(NUM_NODES);
        for i in 0..NUM_NODES {
            result.push(self.get(i));
        }
        result
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

fn compute_mining_seed(header: &[u8], height: u64, nonce: u64) -> Hash {
    let mut data = Vec::with_capacity(48 + header.len());
    data.extend_from_slice(DOMAIN_SEED);
    data.extend_from_slice(header);
    data.extend_from_slice(&height.to_le_bytes());
    data.extend_from_slice(&nonce.to_le_bytes());
    blake3_256(&data)
}

pub fn generate_dataset(seed: &Hash) -> Dataset {
    let mut dataset = Dataset::new();
    let epoch_seed_bytes = seed.as_ref();

    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(DOMAIN_NODE);
    data.extend_from_slice(epoch_seed_bytes);
    data.extend_from_slice(&0u64.to_le_bytes());

    dataset.nodes[0] = blake3_xof(&data, NODE_SIZE);

    for i in 1..NUM_NODES {
        let mut data = Vec::with_capacity(48 + NODE_SIZE);
        data.extend_from_slice(DOMAIN_NODE);
        data.extend_from_slice(epoch_seed_bytes);
        data.extend_from_slice(&dataset.nodes[i - 1]);
        data.extend_from_slice(&i.to_le_bytes());
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
        data.extend_from_slice(&i.to_le_bytes());

        let block_hash = blake3_256(&data);
        let block_extended = blake3_xof(block_hash.as_ref(), CACHE_BLOCK_SIZE);
        cache.data.extend_from_slice(&block_extended);
    }

    cache
}

fn reconstruct_node(_cache: &Cache, epoch_seed: &Hash, index: usize, prev_node: &[u8]) -> Vec<u8> {
    let epoch_seed_bytes = epoch_seed.as_ref();
    let mut data = Vec::with_capacity(48 + NODE_SIZE);
    data.extend_from_slice(DOMAIN_NODE);
    data.extend_from_slice(epoch_seed_bytes);
    data.extend_from_slice(prev_node);
    data.extend_from_slice(&index.to_le_bytes());
    blake3_xof(&data, NODE_SIZE)
}

pub fn generate_program(state: &State) -> Program {
    let words = state.as_u64_array();
    let mut instructions = Vec::with_capacity(PROGRAM_LENGTH);

    for i in 0..PROGRAM_LENGTH {
        let selector = words[i % 8];
        let op_bits = (selector >> (i * 4)) & 0x07;
        let dst = ((selector >> 16) & 0x07) as u8;
        let src = ((selector >> 19) & 0x07) as u8;
        let imm = ((selector >> 24) & 0x3F) as u8;

        let instruction = match op_bits {
            0 => Instruction::Add { dst, src },
            1 => Instruction::Sub { dst, src },
            2 => Instruction::Mul { dst, src },
            3 => Instruction::Xor { dst, src },
            4 => Instruction::Rotl { dst, imm },
            5 => Instruction::Rotr { dst, imm },
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
    let idx1 = words[0].wrapping_add(step) as usize % NUM_NODES;
    let idx2 = words[1].wrapping_mul(step.wrapping_add(1)) as usize % NUM_NODES;
    let idx_write = (words[2] ^ words[3]) as usize % NUM_NODES;
    (idx1, idx2, idx_write)
}

fn node_word_count() -> usize {
    NODE_SIZE / 8
}

fn node_as_u64_array(node: &[u8]) -> &[u64] {
    let word_count = node_word_count();
    let words_ptr = node.as_ptr() as *const u64;
    unsafe { std::slice::from_raw_parts(words_ptr, word_count) }
}

pub fn execute_program(
    state: &mut State,
    program: &Program,
    node1: &[u8],
    node2: &[u8],
) {
    let node1_words = node_as_u64_array(node1);
    let node2_words = node_as_u64_array(node2);
    let state_words = state.as_u64_mut_array();

    for instruction in &program.instructions {
        instruction.execute(state_words, node1_words, node2_words);
    }
}

pub fn apply_branch(
    state: &mut State,
    step: u32,
    node1: &[u8],
    node2: &[u8],
) {
    let words = state.as_u64_array();
    let branch_variant = (words[0] & 0x03) as u8;
    let state_bytes = state.as_bytes();

    let mut input = Vec::with_capacity(16 + 32 + 64);
    input.extend_from_slice(DOMAIN_BRANCH);
    input.extend_from_slice(&step.to_le_bytes());
    input.push(branch_variant);
    match branch_variant {
        0 => input.extend_from_slice(state_bytes),
        1 => {
            input.extend_from_slice(state_bytes);
            input.extend_from_slice(&node1[..32]);
        }
        2 => {
            input.extend_from_slice(state_bytes);
            input.extend_from_slice(&node2[..32]);
        }
        3 => {
            input.extend_from_slice(state_bytes);
            input.extend_from_slice(&node1[..32]);
            input.extend_from_slice(&node2[..32]);
        }
        _ => unreachable!(),
    }

    let output = blake3_xof(&input, STATE_SIZE);
    let state_words = state.as_u64_mut_array();
    for i in 0..8 {
        state_words[i] ^= u64::from_le_bytes(
            output[i * 8..(i + 1) * 8].try_into().unwrap(),
        );
    }
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

pub fn evo_omap_hash(
    dataset: &mut Dataset,
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
        let mut write_data = Vec::with_capacity(8192 + 32);
        write_data.extend_from_slice(&node1[..8192]);
        write_data.extend_from_slice(&state_bytes[..32]);
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
    let memory_commitment = compute_merkle_root(dataset);
    let final_input: Vec<u8> = state_summary
        .as_ref()
        .iter()
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
    let epoch_seed = compute_epoch_seed(height);
    let base_dataset = generate_dataset(&epoch_seed);
    let target = u64::MAX / difficulty;

    let mut cow_dataset = CowDataset::new(&base_dataset);

    for nonce in 0..max_nonce_attempts {
        cow_dataset.reset();

        let mut dataset = Dataset::new();
        for i in 0..NUM_NODES {
            dataset.set(i, cow_dataset.get(i).to_vec());
        }

        let pow_hash = evo_omap_hash(&mut dataset, header, height, nonce);

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
    let epoch_seed = compute_epoch_seed(height);
    let cache = generate_cache(&epoch_seed);
    let mut dataset = Dataset::new();

    let mut prev_node = Vec::new();
    for i in 0..NUM_NODES {
        let node = if i == 0 {
            blake3_xof(
                &[
                    DOMAIN_NODE,
                    epoch_seed.as_ref(),
                    &(0u64).to_le_bytes(),
                ]
                .iter()
                .flat_map(|v| v.iter())
                .cloned()
                .collect::<Vec<u8>>(),
                NODE_SIZE,
            )
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

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(arr[0], 0x0001020304050607u64);
        assert_eq!(arr[1], 0x1011121314151617u64);
        assert_eq!(arr[7], 0x7071727374757677u64);
    }

    #[test]
    fn test_state_from_seed() {
        let seed = Hash([0u8; 32]);
        let state = State::from_seed(&seed);
        let arr = state.as_u64_array();
        assert_ne!(arr, [0u64; 8]);
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
    fn test_different_seeds_different_datasets() {
        let seed0 = compute_epoch_seed(0);
        let seed1 = compute_epoch_seed(1024);
        let ds0 = generate_dataset(&seed0);
        let ds1 = generate_dataset(&seed1);
        assert_ne!(ds0.nodes[0], ds1.nodes[0]);
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
    fn test_derive_indices() {
        let state = State([0u8; 64]);
        let (i1, i2, iw) = derive_indices(&state, 0);
        assert_eq!(i1, 0);
        assert_eq!(i2, 0);
        assert_eq!(iw, 0);
    }

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
    fn test_verify_accepts_valid_proof() {
        let header = b"test header for mining";
        let height = 100u64;
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

    #[test]
    fn test_verify_rejects_invalid_proof() {
        let header = b"test header";
        let height = 100u64;
        let difficulty = 1_000_000u64;
        assert!(!verify(header, height, 0, difficulty));
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
    fn test_dataset_modification_after_hash() {
        let header = b"test header";
        let height = 100u64;
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
        assert_ne!(
            original_node_0, final_node_0,
            "Dataset node should be modified after hash"
        );
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
}
