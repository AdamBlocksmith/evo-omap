# EVO-OMAP Proof-of-Work Algorithm

An execution-based, memory-hard proof-of-work algorithm designed for ASIC and GPU resistance.

## Overview

EVO-OMAP is a proof-of-work algorithm that uses execution-based memory hardness to achieve equitable hashrate distribution across hardware types. The algorithm forces miners to execute a deterministic program that reads and writes a large memory buffer, performs arithmetic with data-dependent branching, and evolves state over thousands of steps.

## Algorithm Properties

| Property | Value |
|----------|-------|
| Dataset Size | Tunable (64 MiB - 1 GiB) |
| Node Size | Tunable (64 KiB - 16 MiB) |
| Cache Size | ~1/8 of dataset |
| Steps per Hash | Tunable (512 - 65536) |
| Program Length | Tunable (4 - 16 instructions) |
| Branch Ways | Tunable (2, 4, or 8) |
| Epoch Length | Tunable (128 - 8192 blocks) |
| Inner Hash | Blake3-256 |
| Final Hash | SHA3-256 |

## Architecture

### Execution Model

Each hash attempt:

1. **Seed Generation**: Derive epoch seed from block height
2. **Dataset Generation**: Generate N chained nodes using Blake3 XOF
3. **State Initialization**: Derive 64-byte state from header + height + nonce
4. **Execution Loop** (N steps):
   - Generate program from current state
   - Derive dataset indices from current state
   - Read two nodes from dataset
   - Execute superscalar program (8 instructions)
   - Apply 4-way data-dependent branch
   - Write one node back to dataset
   - Update rolling commitment
5. **Finalization**: Hash state summary with dataset commitment

### Instruction Set

The algorithm supports 8 instruction types:

| Instruction | Operation | ASIC Impact |
|-------------|-----------|-------------|
| ADD | Wrapping addition | Low |
| SUB | Wrapping subtraction | Low |
| MUL | Wrapping multiplication | Medium |
| XOR | Bitwise XOR | Low |
| ROTL | Data-dependent left rotation | High |
| ROTR | Data-dependent right rotation | High |
| MULH | High 64 bits of 128-bit multiply | Very High |
| SWAP | Exchange two registers | Low |

### Security Features

1. **Memory Hardness**: Large mutable dataset requires RAM
2. **Data-Dependent Branching**: Prevents fixed hardware pipelines
3. **Area-Expensive Operations**: MULH and rotations cost silicon
4. **Sequential Dataset Generation**: Cannot precompute in parallel
5. **State Entanglement**: Each step depends on all prior execution

## Public Specification

The algorithm specification is **public** and includes:

- Algorithm design and step order
- Instruction set and operation semantics
- Parameter valid ranges
- Security properties and rationale
- Domain separators

### Parameter Ranges

```rust
Node Size:      64 KiB - 16 MiB
Dataset Nodes:  16 - 1024
Total Memory:   1 MiB - 1 GiB
Compute Steps:  512 - 65536
Program Length: 4 - 16 instructions
Epoch Length:   128 - 8192 blocks
Branch Ways:    2, 4, or 8
```

## Private Tuning

The **specific configuration values** (exact memory size, steps, etc.) are **private** and should not be published. This prevents attackers from optimizing for a fixed configuration.

Network operators should:

1. Choose values within the public spec ranges
2. Keep specific combinations private
3. Consider versioned parameters per epoch
4. Monitor hashrate distribution

## Implementation Structure

```
src/
├── hash.rs           # Blake3, SHA3-256, XOF functions
├── public_spec.rs   # Algorithm specification (public)
├── private_tuning.rs # Configuration values (private)
├── evo_omap.rs       # Core algorithm implementation
└── main.rs           # CLI interface
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

## Performance

Expected hash rates on common hardware:

| Hardware | Hash Rate | Notes |
|----------|-----------|-------|
| CPU (Ryzen 9) | 150-300 H/s | Branch prediction helps |
| GPU (RTX 4090) | 200-400 H/s | Warp divergence from branching |
| ASIC (hypothetical) | 200-450 H/s | SRAM + branch unit costs |

CPU:GPU ratio is typically 0.75-1.5x depending on CPU model.

## Design Rationale

### Why Memory Size?

Larger memory requirements force ASICs to use expensive SRAM. The algorithm cannot be computed efficiently with DRAM due to the read-write nature and data-dependent access patterns.

### Why Branching?

Four-way branching prevents GPU warp efficiency and ASIC pipeline optimization. CPUs with branch prediction handle this naturally.

### Why MULH?

The 128-bit multiply to get high bits requires significant silicon area on ASICs. This operation is cheap on CPUs with native 128-bit support.

### Why Dataset Chaining?

Each node depends on the previous node, making dataset generation sequential. This prevents miners from precomputing the dataset in parallel.

## License

MIT OR Apache-2.0
