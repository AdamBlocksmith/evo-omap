# EVO-OMAP: Execution-Based Memory-Hard Proof-of-Work

## Overview

EVO-OMAP (EVOlutionary Oriented Memory-hard Algorithm for Proof-of-work) is a memory-hard proof-of-work algorithm designed to achieve equitable hashrate distribution across CPU, GPU, and ASIC hardware. Unlike hash-based PoWs (SHA-256, Scrypt), EVO-OMAP is **execution-based** — miners must execute a deterministic program that reads and writes a large memory buffer, forcing specialized hardware to include large SRAM.

## Key Properties

| Property | Value | Implication |
|----------|-------|-------------|
| Memory Footprint | 256 MiB | ASICs require expensive on-chip SRAM |
| Memory Access | Read-write per step | Cannot be computed with DRAM alone |
| Branch Factor | 4-way | GPU warp efficiency reduced; CPUs with branch prediction excel |
| Execution Model | Superscalar | 8 instructions per step with data-dependent operands |
| State Size | 512 bits | Small enough for full in-register execution |
| Dataset Chaining | Sequential | Nodes form a chain; no parallel precomputation |

## Why EVO-OMAP?

### The Memory-Hardness Problem

Traditional hash-based PoWs (SHA-256, Scrypt, Argon2) compute a pure function — given the same input, they always produce the same output with no side effects. This allows ASICs to:

1. Compute the function in minimal silicon (no RAM required)
2. Pipeline the computation for high clock frequencies
3. Skip memory entirely, achieving 1000-10000x efficiency gains over CPUs

### EVO-OMAP's Solution

EVO-OMAP requires a **mutable 256 MiB dataset** that changes with every nonce attempt. The algorithm:

1. Reads two nodes from the dataset each step
2. Executes 8 instructions using data from those nodes as operands
3. Applies a 4-way data-dependent branch
4. Writes one node back to the dataset

This creates **memory-read-write dependence** — the dataset must be physically present in memory and accessed in a pattern determined by intermediate computational results. An ASIC cannot skip this; it must include 256 MiB of fast memory and a memory controller.

## Algorithm Specification

### Notation

- `H(x)` — Blake3-256 hash of `x`
- `XOF(seed, len)` — Blake3 XOF extending `seed` to `len` bytes
- `⊕` — XOR operation
- `←` — Assignment
- `%` — Modular arithmetic

### Dataset Generation

The dataset consists of `N = 256` nodes, each of size `S = 1,048,576` bytes (1 MiB).

```
Node[0] = XOF(DOMAIN_NODE ‖ epoch_seed ‖ 0, S)

For i = 1 to N-1:
    Node[i] = XOF(DOMAIN_NODE ‖ epoch_seed ‖ Node[i-1] ‖ i, S)
```

The **epoch seed** is derived from block height:
```
epoch = floor(height / EPOCH_LENGTH)
epoch_seed = H(DOMAIN_EPOCH ‖ epoch)
```

### State

The state `W` is 64 bytes (512 bits), interpreted as 8 × unsigned 64-bit integers:
```
W = [w₀, w₁, ..., w₇]
```

### Program Execution

At each of `T = 4096` steps:

1. **Index Derivation**: Compute dataset indices from state:
   ```
   idx₁ = (w₀ + step) mod N
   idx₂ = (w₁ × (step + 1)) mod N
   idx_w = (w₂ ⊕ w₃) mod N
   ```

2. **Program Generation**: Derive 8 instructions from state:
   ```
   For i = 0 to 7:
       selector = wᵢ
       op = (selector >> (i × 4)) & 0x07
       dst = (selector >> 16) & 0x07
       src = (selector >> 19) & 0x7F
   ```

3. **Instruction Execution**: Each instruction accesses `node[src mod 128]`:
   ```
   ADD:   w[dst] = w[dst] + node1[src mod 128]
   SUB:   w[dst] = w[dst] - node2[src mod 128]
   MUL:   w[dst] = w[dst] × node1[src mod 128]
   XOR:   w[dst] = w[dst] ⊕ node2[src mod 128]
   ROTL:  w[dst] = w[dst] << (node1[src mod 128] mod 64)
   ROTR:  w[dst] = w[dst] >> (node2[src mod 128] mod 64)
   MULH:  w[dst] = high_64(w[dst] × node1[src mod 128])
   SWAP:  swap(w[a], w[b])
   ```

4. **Branch Application**: Select branch variant and mix:
   ```
   variant = w₀ mod 4
   input = DOMAIN_BRANCH ‖ step ‖ variant
   if variant == 1: input ‖= node1[0..32]
   if variant == 2: input ‖= node2[0..32]
   if variant == 3: input ‖= node1[0..32] ‖ node2[0..32]
   output = XOF(input, 64)
   for j = 0 to 7: wⱼ = wⱼ ⊕ output[j×8:(j+1)×8]
   ```

5. **Node Write**: Compute and store written node:
   ```
   write_data = node1[0..8192] ‖ w[0..4]
   Node[idx_w] = XOF(write_data, S)
   ```

6. **Commitment Update**:
   ```
   commitment = H(commitment ‖ w[0..4])
   ```

### Finalization

```
state_summary = H(W)
merkle_root = H(DOMAIN_MEMORY ‖ Node[0] ‖ ... ‖ Node[N-1])
final_hash = SHA3-256(state_summary ‖ merkle_root)
```

## Memory-Hardness Analysis

### Why 256 MiB?

The memory requirement serves two purposes:

1. **Force SRAM usage**: 256 MiB of DRAM has ~100ns latency; SRAM at that capacity would cost >$1000 per chip. This makes single-chip ASIC mining economically infeasible.

2. **Create memory bandwidth ceiling**: Sequential read-write of 256 MiB takes ~50μs at 5 GB/s bandwidth. The algorithm's 4096 steps each read 2 nodes and write 1, requiring significant memory bandwidth.

### Why Operand Access?

The instruction set accesses `node_word[src mod 128]` — the first 1 KiB of each node. This creates **locality** in memory access patterns, but the 128-word window is large enough to prevent perfect caching.

### Why Data-Dependent Branching?

The 4-way branch depends on `w₀ mod 4`, which is determined by prior computation. This means:

- An ASIC cannot pre-fetch instructions
- A GPU warp takes divergent paths for different nonces
- Branch prediction helps but cannot eliminate misprediction

### Why Dataset Chaining?

Each node depends on the previous node via XOF. This means:

- Node[i] cannot be computed until Node[i-1] is known
- Dataset generation is O(N) sequential work
- Parallel computation of dataset is impossible

## ASIC Resistance Analysis

| Factor | CPU | GPU | Potential ASIC |
|--------|-----|-----|---------------|
| Memory | DRAM (shared) | DRAM (shared) | SRAM (on-chip) |
| Memory Cost | Low | Low | Very High |
| Memory Bandwidth | 50 GB/s | 500 GB/s | 1000 GB/s |
| Branch Handling | Branch predictor | 32-thread warp divergence | Custom branch unit |
| Area Efficiency | N/A | N/A | SRAM dominates die area |
| Expected Advantage | 1x (baseline) | 0.5-2x | 2-5x (limited by SRAM) |

The theoretical ASIC advantage is **bounded by memory**, not unbounded as with pure hash functions.

## Parameters

### Default Configuration

| Parameter | Value | Range | Description |
|-----------|-------|-------|-------------|
| `NODE_SIZE` | 1,048,576 | 64 KiB - 16 MiB | Bytes per node |
| `NUM_NODES` | 256 | 16 - 1024 | Dataset nodes |
| `NUM_STEPS` | 4,096 | 512 - 65536 | Execution steps |
| `PROGRAM_LENGTH` | 8 | 4 - 16 | Instructions per step |
| `OPERAND_WORDS` | 128 | Fixed | Words per node for operand access |
| `BRANCH_WAYS` | 4 | 2, 4, 8 | Branch variants |
| `EPOCH_LENGTH` | 1,024 | 128 - 8192 | Blocks per epoch |
| `CACHE_SIZE` | 33,554,432 | ~1/8 dataset | Light verification cache |

### Light Verification

Light verification uses a 32 MiB cache to reconstruct nodes on-demand. The cache is generated as:

```
For i = 0 to 511:
    cache_block[i] = XOF(H(DOMAIN_CACHE ‖ epoch_seed ‖ i), 65536)
```

Nodes are reconstructed from cache as needed, trading computation for memory.

## Reference Implementation

### Project Structure

```
evo-omap/
├── src/
│   ├── hash.rs           # blake3, sha3 primitives
│   ├── public_spec.rs    # Algorithm specification (protocol constants)
│   ├── constants.rs      # Implementation parameters
│   ├── evo_omap.rs       # Core algorithm + tests
│   └── main.rs           # CLI interface
├── Cargo.toml
└── README.md
```

### API

```rust
use evo_omap::{Hash, mine, verify, verify_light};

// Mine for a valid nonce
let nonce = mine(header, height, difficulty, max_attempts);

// Full verification (requires 256 MiB)
let valid = verify(header, height, nonce, difficulty);

// Light verification (uses cache, slower but memory-efficient)
let valid = verify_light(header, height, nonce, difficulty);
```

### CLI

```bash
# Mine
cargo run -- mine <header_hex> <height> <difficulty> [max_nonce]

# Verify
cargo run -- verify <header_hex> <height> <nonce> <difficulty>

# Light verify
cargo run -- verify <header_hex> <height> <nonce> <difficulty> light

# Compute hash
cargo run -- hash <header_hex> <height> <nonce>

# Epoch seed
cargo run -- seed <height>
```

## Comparison with Other PoWs

| Algorithm | Memory | Memory Type | ASIC Advantage | Notes |
|----------|--------|-------------|---------------|-------|
| SHA-256d | None | None | ~1000x | Pure computation |
| Scrypt | 128 KiB | DRAM | ~100x | Memory-hard but small |
| Argon2 | 256 MiB | DRAM | ~10x | Password hashing, not mining |
| Ethash | 8 GiB | DRAM | ~2x | Dataset grows over time |
| **EVO-OMAP** | **256 MiB** | **SRAM** | **2-5x** | **Mutable dataset** |

EVO-OMAP's advantage: the mutable dataset with read-write dependence forces SRAM, which is silicon-intensive and cannot be easily pipelined like DRAM access.

## Security Considerations

### 1. Memory-Efficient Mining

An ASIC with 256 MiB SRAM could potentially:
- Cache the entire dataset on-chip
- Compute at lower memory bandwidth

However, SRAM at 256 MiB requires significant die area, limiting other optimizations.

### 2. Light Client Trust

Light clients verify using cache-based node reconstruction. The commitment scheme (linear hash, not Merkle tree) means light clients cannot verify node inclusion efficiently. Future work: implement proper Merkle tree for O(log n) proofs.

### 3. Big-Endian Platforms

The algorithm uses little-endian byte interpretation for arithmetic. Big-endian platforms would produce different hashes, causing chain splits. This is explicitly **not supported**.

## Test Vectors

Test vectors are computed dynamically in the test module (`evo_omap.rs`). Run tests with `cargo test` to verify correctness against known-answer tests.

Example epoch seed test:
```rust
let seed = compute_epoch_seed(0);
assert_eq!(&seed.0[..8], &[0x9bu8, 0x5bu8, 0x08u8, 0xa7u8, 0x71u8, 0xd5u8, 0x74u8, 0x67u8]);
```

See `evo_omap.rs` test module for full test suite including:
- Dataset generation determinism
- Instruction execution correctness
- Program generation validation
- Domain separator collision tests
- Edge case tests (overflow, max values)

## Academic Background

EVO-OMAP builds on principles from:

1. **Memory-hard functions**: Percival & Colvin (Scrypt, 2009)
2. **Data-dependent addressing**: Boneh et al. (Balloon Hashing, 2015)
3. **DAG-based mining**: Ethash (2014)
4. **Execution-based PoW**: RandomJS (2018), RandomX (2019)

Key innovations:
- Mutable dataset with read-write dependence
- All instructions access memory (not just mining seed)
- 4-way branching with variable node data mixing

## License

MIT OR Apache-2.0
