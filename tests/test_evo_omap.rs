use evo_omap::{
    compute_epoch_seed, generate_dataset, generate_cache, generate_program,
    derive_indices, execute_program, apply_branch, compute_merkle_root,
    evo_omap_hash, verify, verify_light,
    Dataset, State, Program, Instruction,
    NODE_SIZE, NUM_NODES, CACHE_SIZE, NUM_STEPS, PROGRAM_LENGTH,
    EPOCH_LENGTH, STATE_SIZE,
};

#[test]
fn test_epoch_seed_computation() {
    let seed0 = compute_epoch_seed(0);
    let seed1 = compute_epoch_seed(1);
    let seed1023 = compute_epoch_seed(1023);
    let seed1024 = compute_epoch_seed(1024);

    assert_eq!(seed0, seed1);
    assert_eq!(seed0, seed1023);
    assert_ne!(seed0, seed1024);
}

#[test]
fn test_epoch_boundary() {
    let seed1023 = compute_epoch_seed(1023);
    let seed1024 = compute_epoch_seed(1024);
    assert_ne!(seed1023, seed1024);

    let seed2047 = compute_epoch_seed(2047);
    let seed2048 = compute_epoch_seed(2048);
    assert_ne!(seed2047, seed2048);
}

#[test]
fn test_dataset_deterministic() {
    let seed = compute_epoch_seed(0);
    let ds1 = generate_dataset(&seed);
    let ds2 = generate_dataset(&seed);

    assert_eq!(ds1.nodes.len(), NUM_NODES);
    assert_eq!(ds1.nodes.len(), ds2.nodes.len());

    for i in 0..NUM_NODES {
        assert_eq!(ds1.nodes[i], ds2.nodes[i], "Node {} should be deterministic", i);
    }
}

#[test]
fn test_dataset_node_sizes() {
    let seed = compute_epoch_seed(0);
    let ds = generate_dataset(&seed);

    for i in 0..NUM_NODES {
        assert_eq!(ds.nodes[i].len(), NODE_SIZE, "Node {} should be 1 MiB", i);
    }
}

#[test]
fn test_cache_size() {
    let seed = compute_epoch_seed(0);
    let cache = generate_cache(&seed);
    assert_eq!(cache.data.len(), CACHE_SIZE);
}

#[test]
fn test_state_conversion() {
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
    assert_eq!(arr[7], 0x7071727374757677u64);
}

#[test]
fn test_program_generation_deterministic() {
    let seed = compute_epoch_seed(0);
    let state = State::from_seed(&seed);
    let p1 = generate_program(&state);
    let p2 = generate_program(&state);
    assert_eq!(p1.instructions, p2.instructions);
}

#[test]
fn test_program_has_correct_length() {
    let seed = compute_epoch_seed(0);
    let state = State::from_seed(&seed);
    let program = generate_program(&state);
    assert_eq!(program.instructions.len(), PROGRAM_LENGTH);
}

#[test]
fn test_derive_indices() {
    let state_bytes = [0u8; 64];
    let state = State(state_bytes);
    let (i1, i2, iw) = derive_indices(&state, 0);
    assert_eq!(i1, 0);
    assert_eq!(i2, 0);
    assert_eq!(iw, 0);
}

#[test]
fn test_derive_indices_different_steps() {
    let seed = compute_epoch_seed(0);
    let state = State::from_seed(&seed);

    let (i1_0, _, _) = derive_indices(&state, 0);
    let (i1_1, _, _) = derive_indices(&state, 1);

    assert_ne!(i1_0, i1_1);
}

#[test]
fn test_execute_program_modifies_state() {
    let seed = compute_epoch_seed(0);
    let state_orig = State::from_seed(&seed);
    let state_copy = state_orig.clone();
    let mut state = state_orig;

    let node1 = vec![0u8; NODE_SIZE];
    let node2 = vec![0u8; NODE_SIZE];
    let program = generate_program(&state_copy);

    execute_program(&mut state, &program, &node1, &node2);

    let orig_words = state_copy.as_u64_array();
    let new_words = state.as_u64_array();

    let mut any_different = false;
    for i in 0..8 {
        if orig_words[i] != new_words[i] {
            any_different = true;
            break;
        }
    }
    assert!(any_different, "State should be modified by program execution");
}

#[test]
fn test_apply_branch_changes_state() {
    let seed = compute_epoch_seed(0);
    let state_orig = State::from_seed(&seed);
    let state_copy = state_orig.clone();
    let mut state = state_orig;

    let node1 = vec![0u8; NODE_SIZE];
    let node2 = vec![0u8; NODE_SIZE];

    apply_branch(&mut state, 0, &node1, &node2);

    let orig_words = state_copy.as_u64_array();
    let new_words = state.as_u64_array();

    let mut any_different = false;
    for i in 0..8 {
        if orig_words[i] != new_words[i] {
            any_different = true;
            break;
        }
    }
    assert!(any_different, "State should be modified by branch");
}

#[test]
fn test_chained_dataset_generation() {
    let seed = compute_epoch_seed(0);
    let ds = generate_dataset(&seed);

    for i in 1..NUM_NODES {
        assert_ne!(ds.nodes[i - 1], ds.nodes[i], "Consecutive nodes should differ");
    }
}

#[test]
fn test_different_epochs_different_datasets() {
    let seed0 = compute_epoch_seed(0);
    let seed1024 = compute_epoch_seed(1024);

    let ds0 = generate_dataset(&seed0);
    let ds1024 = generate_dataset(&seed1024);

    assert_ne!(ds0.nodes[0], ds1024.nodes[0]);
    assert_ne!(ds0.nodes[255], ds1024.nodes[255]);
}

#[test]
fn test_full_hash_deterministic() {
    let header = b"test header for evo-omap";
    let height = 100u64;
    let nonce = 42u64;

    let seed = compute_epoch_seed(height);
    let mut ds1 = generate_dataset(&seed);
    let mut ds2 = generate_dataset(&seed);

    let h1 = evo_omap_hash(&mut ds1, header, height, nonce);
    let h2 = evo_omap_hash(&mut ds2, header, height, nonce);

    assert_eq!(h1, h2, "Same inputs should produce same hash");
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
    let seed1 = compute_epoch_seed(1024);

    let mut ds0 = generate_dataset(&seed0);
    let mut ds1 = generate_dataset(&seed1);

    let h0 = evo_omap_hash(&mut ds0, header, 0, nonce);
    let h1 = evo_omap_hash(&mut ds1, header, 1024, nonce);

    assert_ne!(h0, h1);
}

#[test]
fn test_verify_rejects_invalid_proof() {
    let header = b"test header";
    let height = 100u64;
    let difficulty = 1_000_000u64;

    assert!(!verify(header, height, 0, difficulty));
}

#[test]
fn test_verify_accepts_mined_proof() {
    let header = b"test header for mining";
    let height = 100u64;
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
    }
}

#[test]
fn test_light_verification_matches_full() {
    let header = b"test header for light verification";
    let height = 50u64;
    let difficulty = 1u64;
    let target = u64::MAX / difficulty;

    let seed = compute_epoch_seed(height);
    let base_ds = generate_dataset(&seed);

    let mut found_nonce = None;
    for nonce in 0..200_000u64 {
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
fn test_dataset_modified_after_hash() {
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

    assert_ne!(original_node_0, final_node_0, "Dataset should be modified after hash");
}

#[test]
fn test_merkle_root_computation() {
    let seed = compute_epoch_seed(0);
    let ds = generate_dataset(&seed);
    let root1 = compute_merkle_root(&ds);
    let root2 = compute_merkle_root(&ds);
    assert_eq!(root1, root2);

    let seed2 = compute_epoch_seed(1024);
    let ds2 = generate_dataset(&seed2);
    let root3 = compute_merkle_root(&ds2);
    assert_ne!(root1, root3);
}

#[test]
fn test_all_instruction_types() {
    let mut state = State([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                           0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
                           0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB, 0xED, 0x0F,
                           0x31, 0x53, 0x75, 0x97, 0xB9, 0xDB, 0xFD, 0x1F,
                           0x41, 0x63, 0x85, 0xA7, 0xC9, 0xEB, 0x0D, 0x2F,
                           0x51, 0x73, 0x95, 0xB7, 0xD9, 0xFB, 0x1D, 0x3F,
                           0x61, 0x83, 0xA5, 0xC7, 0xE9, 0x0B, 0x2D, 0x4F]);

    let node1 = vec![0xFFu8; NODE_SIZE];
    let node2 = vec![0xAAu8; NODE_SIZE];

    let program = Program {
        instructions: [
            Instruction::Add { dst: 0, src: 0 },
            Instruction::Sub { dst: 1, src: 1 },
            Instruction::Mul { dst: 2, src: 2 },
            Instruction::Xor { dst: 3, src: 3 },
            Instruction::Rotl { dst: 4, imm: 5 },
            Instruction::Rotr { dst: 5, imm: 3 },
            Instruction::Mulh { dst: 6, src: 6 },
            Instruction::Swap { a: 1, b: 2 },
        ],
    };

    execute_program(&mut state, &program, &node1, &node2);

    let new = state.as_u64_array();

    assert_ne!(0x0123456789ABCDEFu64, new[0], "Add should modify state[0]");
    assert_ne!(0x1122334455667788u64, new[1], "Sub should modify state[1]");
    assert_ne!(0x123456789ABCDEF0u64, new[2], "Mul should modify state[2]");
    assert_ne!(0x21436587A9CBED0Fu64, new[3], "Xor should modify state[3]");
    assert_ne!(0x31537597B9DBFD1Fu64, new[4], "Rotl should modify state[4]");
    assert_ne!(0x416385A7C9EB0D2Fu64, new[5], "Rotr should modify state[5]");
    assert_ne!(0x517395B7D9FB1D3Fu64, new[6], "Mulh should modify state[6]");

    assert_ne!(0x0123456789ABCDEFu64, new[7], "Swap should affect state[7] via Swap(1,2)");
}

#[test]
fn test_constants_match_spec() {
    assert_eq!(NODE_SIZE, 1_048_576);
    assert_eq!(NUM_NODES, 256);
    assert_eq!(CACHE_SIZE, 33_554_432);
    assert_eq!(NUM_STEPS, 4_096);
    assert_eq!(PROGRAM_LENGTH, 8);
    assert_eq!(EPOCH_LENGTH, 1_024);
    assert_eq!(STATE_SIZE, 64);
}
