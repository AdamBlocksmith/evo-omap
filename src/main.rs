use std::env;
use std::process;

use evo_omap::{mine, verify, verify_light, compute_epoch_seed, generate_dataset, evo_omap_hash};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("EVO-OMAP Proof-of-Work");
        eprintln!("Usage:");
        eprintln!("  {} mine <header_hex> <height> <difficulty> [max_nonce]", args[0]);
        eprintln!("  {} verify <header_hex> <height> <nonce> <difficulty> [light]", args[0]);
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  {} mine 00 0 1 1000000", args[0]);
        eprintln!("  {} verify 00 0 12345 1", args[0]);
        process::exit(1);
    }

    match args[1].as_str() {
        "mine" => {
            if args.len() < 5 {
                eprintln!("Usage: {} mine <header_hex> <height> <difficulty> [max_nonce]", args[0]);
                process::exit(1);
            }
            let header_hex = &args[2];
            let height: u64 = args[3].parse().expect("Invalid height");
            let difficulty: u64 = args[4].parse().expect("Invalid difficulty");
            let max_nonce: u64 = if args.len() > 5 {
                args[5].parse().unwrap_or(10_000_000)
            } else {
                10_000_000
            };

            let header = match hex::decode(header_hex) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("Invalid hex: {}", e);
                    process::exit(1);
                }
            };

            println!("Mining...");
            println!("Header: {}", header_hex);
            println!("Height: {}", height);
            println!("Difficulty: {}", difficulty);
            println!("Max nonce attempts: {}", max_nonce);
            println!();

            match mine(&header, height, difficulty, max_nonce) {
                Some(nonce) => {
                    println!("Found valid nonce: {}", nonce);
                    println!("Nonce (hex): 0x{:x}", nonce);
                }
                None => {
                    println!("No valid nonce found in {} attempts.", max_nonce);
                    process::exit(1);
                }
            }
        }

        "verify" => {
            if args.len() < 6 {
                eprintln!("Usage: {} verify <header_hex> <height> <nonce> <difficulty> [light]", args[0]);
                process::exit(1);
            }
            let header_hex = &args[2];
            let height: u64 = args[3].parse().expect("Invalid height");
            let nonce: u64 = args[4].parse().expect("Invalid nonce");
            let difficulty: u64 = args[5].parse().expect("Invalid difficulty");
            let light = args.len() > 6 && args[6] == "light";

            let header = match hex::decode(header_hex) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("Invalid hex: {}", e);
                    process::exit(1);
                }
            };

            let valid = if light {
                println!("Verifying with light mode (cache-based)...");
                verify_light(&header, height, nonce, difficulty)
            } else {
                println!("Verifying with full mode (dataset-based)...");
                verify(&header, height, nonce, difficulty)
            };

            if valid {
                println!("Proof-of-work is VALID");
                println!("Epoch seed: {}", hex::encode(compute_epoch_seed(height).0));
            } else {
                println!("Proof-of-work is INVALID");
                process::exit(1);
            }
        }

        "hash" => {
            if args.len() < 5 {
                eprintln!("Usage: {} hash <header_hex> <height> <nonce>", args[0]);
                process::exit(1);
            }
            let header_hex = &args[2];
            let height: u64 = args[3].parse().expect("Invalid height");
            let nonce: u64 = args[4].parse().expect("Invalid nonce");

            let header = match hex::decode(header_hex) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("Invalid hex: {}", e);
                    process::exit(1);
                }
            };

            let epoch_seed = compute_epoch_seed(height);
            let mut dataset = generate_dataset(&epoch_seed);
            let hash = evo_omap_hash(&mut dataset, &header, height, nonce);

            println!("Hash: {}", hex::encode(hash.0));
        }

        "seed" => {
            if args.len() < 3 {
                eprintln!("Usage: {} seed <height>", args[0]);
                process::exit(1);
            }
            let height: u64 = args[2].parse().expect("Invalid height");
            let seed = compute_epoch_seed(height);
            println!("Epoch seed: {}", hex::encode(seed.0));
        }

        _ => {
            eprintln!("Unknown command: {}", args[1]);
            eprintln!("Valid commands: mine, verify, hash, seed");
            process::exit(1);
        }
    }
}