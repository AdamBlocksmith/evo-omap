# EVO-OMAP Proof-of-Work Algorithm

An execution-based, memory-hard proof-of-work algorithm designed for ASIC and GPU resistance.

## Overview

EVO-OMAP is a proof-of-work algorithm that uses execution-based memory hardness to achieve equitable hashrate distribution across hardware types. The algorithm forces miners to execute a deterministic program that reads and writes a large memory buffer, performs arithmetic with data-dependent branching, and evolves state over thousands of steps.

## Algorithm Properties

| Property | Value |
|----------|-------|
| Dataset Size | 256 MiB (configurable) |
| Node Size | 1 MiB (configurable) |
| Cache Size | 32 MiB (configurable) |
| Steps per Hash | 4,096 (configurable) |
| Program Length | 8 instructions (configurable) |
| Epoch Length | 1,024 blocks (configurable) |
| Inner Hash | Blake3-256 |
| Final Hash | SHA3-256 |

## Architecture

### Execution Model

Each hash attempt:

1. **Seed Generation**: Derive epoch seed from block height
2. **Dataset Generation**: Generate 256 chained nodes using Blake3 XOF
3. **State Initialization**: Derive 64-byte state from header + height + nonce
4. **Execution Loop** (4,096 steps):
   - Generate program from current state (8 instructions)
   - Derive dataset indices from current state
   - Read two nodes from dataset (operand access: src % 128)
   - Execute superscalar program
   - Apply 4-way data-dependent branch (XOR mix)
   - Write one node back to dataset
   - Update rolling commitment
5. **Finalization**: Hash state summary with dataset commitment

### Instruction Set

All 8 instruction types access node data for memory-hardness:

| Instruction | Operation | Source |
|-------------|-----------|--------|
| ADD | Wrapping addition | node1[src % 128] |
| SUB | Wrapping subtraction | node2[src % 128] |
| MUL | Wrapping multiplication | node1[src % 128] |
| XOR | Bitwise XOR | node2[src % 128] |
| ROTL | Data-dependent left rotation | node1[src % 128] % 64 |
| ROTR | Data-dependent right rotation | node2[src % 128] % 64 |
| MULH | High 64 bits of 128-bit multiply | node1[src % 128] |
| SWAP | Exchange two registers | register file only |

### Security Features

1. **Memory Hardness**: 256 MiB mutable dataset requires RAM
2. **Data-Dependent Branching**: 4-way branch depends on node data
3. **All Instructions Access Memory**: ROT reads node_word for rotation amount
4. **Area-Expensive Operations**: MULH costs significant silicon
5. **Sequential Dataset Generation**: Cannot precompute nodes in parallel
6. **State Entanglement**: Each step depends on all prior execution

## Public Constants

All protocol constants are public in `src/constants.rs`:

```rust
pub const NODE_SIZE: usize = 1_048_576;      // 1 MiB per node
pub const NUM_NODES: usize = 256;            // 256 nodes
pub const NUM_STEPS: usize = 4_096;          // 4,096 execution steps
pub const PROGRAM_LENGTH: usize = 8;          // 8 instructions per program
pub const OPERAND_WORDS: usize = 128;        // 128 u64 words per node (1 KiB working set)
pub const BRANCH_WAYS: usize = 4;           // 4-way branching
```

## Implementation Structure

```
src/
├── hash.rs           # Blake3, SHA3-256, XOF functions
├── public_spec.rs   # Algorithm specification (public)
├── constants.rs     # Protocol constants (public)
├── evo_omap.rs     # Core algorithm implementation
└── main.rs         # CLI interface
```

## CLI Usage

```bash
# Mine for a valid nonce
cargo run -- mine <header_hex> <height> <difficulty> [max_nonce]

# Verify a proof
cargo run -- verify <header_hex> <height> <nonce> <difficulty> [light]

# Compute hash directly
cargo run -- hash <header_hex> <height> <nonce>

# Get epoch seed for a height
cargo run -- seed <height>
```

## Testing

```bash
# Run all tests
cargo test

# Run only library tests
cargo test --lib

# Run specific test
cargo test test_name
```

## Design Rationale

### Why Memory Size?

256 MiB mutable dataset forces ASICs to use expensive SRAM. DRAM cannot be used efficiently due to read-write nature and data-dependent access patterns.

### Why All Instructions Access Memory?

ROTL/ROTR read node_word[src % 128] % 64 for rotation amount. This ensures every instruction type requires memory access, preventing ASIC pipelines from skipping memory ops.

### Why 4-Way Branching?

Branch variant mixes state with 0, 32, 32, or 64 bytes of node data depending on variant. This creates varying memory dependence per step.

### Why Dataset Chaining?

Each node depends on the previous node via Blake3 XOF, making dataset generation sequential. Miners cannot precompute the dataset in parallel.

## License

MIT OR Apache-2.0
