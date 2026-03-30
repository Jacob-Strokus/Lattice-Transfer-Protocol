//! LTP Production Rust Benchmark
//!
//! Uses real, production-grade cryptographic implementations to establish
//! production performance baselines for the Lattice Transfer Protocol.
//!
//! Unlike the Python PoC (which simulates ML-KEM/ML-DSA via BLAKE2b and uses
//! pure-Python Reed-Solomon), this suite exercises actual lattice arithmetic
//! and native GF(256) operations — reflecting real deployment performance.
//!
//! Libraries:
//!   blake3                v1.x        — BLAKE3-256 content addressing
//!   chacha20poly1305      v0.10       — ChaCha20-Poly1305 AEAD shard encryption
//!   reed-solomon-erasure  v6          — RS(n=8, k=4) over GF(256)
//!   ml-kem                v0.3.0-rc.1 — ML-KEM-768 (FIPS 203) real lattice KEM
//!   fips204               v0.4        — ML-DSA-65 (FIPS 204) real lattice signatures
//!
//! Statistics: median (p50), p95, sample stddev over N iterations.
//! Cache busting: fresh random input generated before each timed iteration.

use std::time::Instant;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem},
    MlKem768,
};
use rand::{rngs::OsRng, RngCore};
use reed_solomon_erasure::galois_8::ReedSolomon;

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};

// ── Benchmark configuration ───────────────────────────────────────────────────

const WARMUP: usize = 5;
const FAST_ITERS: usize = 200; // sub-ms operations
const MEDIUM_ITERS: usize = 50; // 1–100 ms operations
const SLOW_ITERS: usize = 10; // >100 ms operations

// ── Statistics ────────────────────────────────────────────────────────────────

/// Returns (median, p95, sample_stddev) of timing samples in milliseconds.
fn stats(mut samples: Vec<f64>) -> (f64, f64, f64) {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = samples.len();
    let median = if n % 2 == 0 {
        (samples[n / 2 - 1] + samples[n / 2]) / 2.0
    } else {
        samples[n / 2]
    };
    let p95_idx = ((n as f64 * 0.95).ceil() as usize).saturating_sub(1).min(n - 1);
    let p95 = samples[p95_idx];
    let mean = samples.iter().sum::<f64>() / n as f64;
    let stddev = if n > 1 {
        (samples.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64).sqrt()
    } else {
        0.0
    };
    (median, p95, stddev)
}

fn throughput_mb_s(bytes: usize, ms: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / (ms / 1000.0)
}

fn hr() {
    println!("{}", "\u{2500}".repeat(72));
}

// ── §1  BLAKE3-256 Hash Throughput ───────────────────────────────────────────

fn bench_blake3() {
    println!("\n=== BLAKE3-256 Hash Throughput (blake3 crate) ===");
    println!(
        "  {:>10}  {:>10}  {:>10}  {:>10}  {:>10}",
        "Size", "Median", "p95", "+/-Stddev", "MB/s"
    );
    hr();

    let sizes: &[(usize, &str)] = &[
        (1 << 10, "1.0 KB"),
        (1 << 16, "64.0 KB"),
        (1 << 20, "1.0 MB"),
        (10 << 20, "10.0 MB"),
    ];

    for &(size, label) in sizes {
        // Warmup with cache-busted inputs
        for _ in 0..WARMUP {
            let mut data = vec![0u8; size];
            OsRng.fill_bytes(&mut data);
            let _ = blake3::hash(&data);
        }
        // Measure — fresh random data per iteration
        let samples: Vec<f64> = (0..FAST_ITERS)
            .map(|_| {
                let mut data = vec![0u8; size];
                OsRng.fill_bytes(&mut data);
                let t = Instant::now();
                let _ = blake3::hash(&data);
                t.elapsed().as_secs_f64() * 1000.0
            })
            .collect();

        let (med, p95, std) = stats(samples);
        println!(
            "  {:>10}  {:>7.3} ms  {:>7.3} ms  {:>7.3} ms  {:>10.1}",
            label,
            med,
            p95,
            std,
            throughput_mb_s(size, med),
        );
    }
}

// ── §2  AEAD ChaCha20-Poly1305 Throughput ────────────────────────────────────

fn bench_aead() {
    println!("\n=== AEAD ChaCha20-Poly1305 Encrypt / Decrypt (chacha20poly1305 crate) ===");

    let sizes: &[(usize, &str)] = &[
        (1 << 10, "1.0 KB"),
        (1 << 16, "64.0 KB"),
        (1 << 20, "1.0 MB"),
    ];

    for &(size, label) in sizes {
        // Encrypt — fresh key+nonce+plaintext each iteration (cache busting)
        for _ in 0..WARMUP {
            let key = ChaCha20Poly1305::generate_key(&mut OsRng);
            let cipher = ChaCha20Poly1305::new(&key);
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let mut pt = vec![0u8; size];
            OsRng.fill_bytes(&mut pt);
            let _ = cipher.encrypt(&nonce, pt.as_ref()).unwrap();
        }
        let enc_samples: Vec<f64> = (0..MEDIUM_ITERS)
            .map(|_| {
                let key = ChaCha20Poly1305::generate_key(&mut OsRng);
                let cipher = ChaCha20Poly1305::new(&key);
                let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                let mut pt = vec![0u8; size];
                OsRng.fill_bytes(&mut pt);
                let t = Instant::now();
                let _ = cipher.encrypt(&nonce, pt.as_ref()).unwrap();
                t.elapsed().as_secs_f64() * 1000.0
            })
            .collect();

        // Decrypt — pre-encrypt once, time only decrypt path
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut pt = vec![0u8; size];
        OsRng.fill_bytes(&mut pt);
        let ct = cipher.encrypt(&nonce, pt.as_ref()).unwrap();

        for _ in 0..WARMUP {
            let _ = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        }
        let dec_samples: Vec<f64> = (0..MEDIUM_ITERS)
            .map(|_| {
                let t = Instant::now();
                let _ = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
                t.elapsed().as_secs_f64() * 1000.0
            })
            .collect();

        let (enc_med, _enc_p95, enc_std) = stats(enc_samples);
        let (dec_med, _dec_p95, dec_std) = stats(dec_samples);

        println!(
            "  {:>10}  enc {:>7.3} ms +/-{:.3} ({:>7.1} MB/s)  dec {:>7.3} ms +/-{:.3} ({:>7.1} MB/s)",
            label,
            enc_med,
            enc_std,
            throughput_mb_s(size, enc_med),
            dec_med,
            dec_std,
            throughput_mb_s(size, dec_med),
        );
    }
}

// ── §3  Reed-Solomon RS(n=8, k=4) ────────────────────────────────────────────

fn bench_rs() {
    println!("\n=== Reed-Solomon Erasure Coding RS(n=8, k=4) over GF(256) (reed-solomon-erasure crate) ===");

    let rs = ReedSolomon::new(4, 4).expect("RS construction");

    let sizes: &[(usize, &str)] = &[
        (1 << 10, "1.0 KB"),
        (1 << 16, "64.0 KB"),
        (1 << 20, "1.0 MB"),
    ];

    for &(size, label) in sizes {
        let shard_size = (size + 3) / 4;

        // Encode
        for _ in 0..WARMUP {
            let mut data = vec![0u8; size];
            OsRng.fill_bytes(&mut data);
            let _ = encode_shards(&rs, &data, shard_size);
        }
        let enc_samples: Vec<f64> = (0..SLOW_ITERS)
            .map(|_| {
                let mut data = vec![0u8; size];
                OsRng.fill_bytes(&mut data);
                let t = Instant::now();
                let _ = encode_shards(&rs, &data, shard_size);
                t.elapsed().as_secs_f64() * 1000.0
            })
            .collect();

        // Decode: drop data shards 0-3, reconstruct from parity shards 4-7
        let mut data = vec![0u8; size];
        OsRng.fill_bytes(&mut data);
        let encoded = encode_shards(&rs, &data, shard_size);

        for _ in 0..WARMUP {
            let _ = reconstruct_from_parity(&rs, &encoded);
        }
        let dec_samples: Vec<f64> = (0..SLOW_ITERS)
            .map(|_| {
                let t = Instant::now();
                let _ = reconstruct_from_parity(&rs, &encoded);
                t.elapsed().as_secs_f64() * 1000.0
            })
            .collect();

        let (enc_med, _enc_p95, enc_std) = stats(enc_samples);
        let (dec_med, _dec_p95, dec_std) = stats(dec_samples);

        println!(
            "  {:>10} -> 8 x {:>6}B  enc {:>8.3} ms +/-{:.3} ({:>5.1} MB/s)  dec {:>8.3} ms +/-{:.3} ({:>5.1} MB/s)",
            label,
            shard_size,
            enc_med,
            enc_std,
            throughput_mb_s(size, enc_med),
            dec_med,
            dec_std,
            throughput_mb_s(size, dec_med),
        );
    }
}

fn encode_shards(rs: &ReedSolomon, data: &[u8], shard_size: usize) -> Vec<Vec<u8>> {
    let mut shards: Vec<Vec<u8>> = (0..4)
        .map(|i| {
            let start = i * shard_size;
            let end = ((i + 1) * shard_size).min(data.len());
            let mut s = data[start..end].to_vec();
            s.resize(shard_size, 0);
            s
        })
        .collect();
    for _ in 0..4 {
        shards.push(vec![0u8; shard_size]);
    }
    rs.encode(&mut shards).unwrap();
    shards
}

fn reconstruct_from_parity(rs: &ReedSolomon, encoded: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut shards_opt: Vec<Option<Vec<u8>>> = encoded
        .iter()
        .enumerate()
        .map(|(i, s)| if i < 4 { None } else { Some(s.clone()) })
        .collect();
    rs.reconstruct(&mut shards_opt).unwrap();
    shards_opt.into_iter().map(|s| s.unwrap()).collect()
}

// ── §4  ML-KEM-768 (FIPS 203) ────────────────────────────────────────────────

fn bench_mlkem() {
    println!("\n=== ML-KEM-768 (FIPS 203) — Real Lattice Arithmetic (ml-kem crate) ===");

    // Key generation
    for _ in 0..WARMUP {
        let _ = MlKem768::generate_keypair();
    }
    let kg_samples: Vec<f64> = (0..MEDIUM_ITERS)
        .map(|_| {
            let t = Instant::now();
            let _ = MlKem768::generate_keypair();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();

    let (dk, ek) = MlKem768::generate_keypair();

    // Encapsulation
    for _ in 0..WARMUP {
        let _ = ek.encapsulate();
    }
    let enc_samples: Vec<f64> = (0..FAST_ITERS)
        .map(|_| {
            let t = Instant::now();
            let _ = ek.encapsulate();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();

    // Decapsulation — reuse same ct
    let (ct, _ss) = ek.encapsulate();
    for _ in 0..WARMUP {
        let _ = dk.decapsulate(&ct);
    }
    let dec_samples: Vec<f64> = (0..FAST_ITERS)
        .map(|_| {
            let t = Instant::now();
            let _ = dk.decapsulate(&ct);
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();

    let (kg_med, kg_p95, kg_std) = stats(kg_samples);
    let (enc_med, enc_p95, enc_std) = stats(enc_samples);
    let (dec_med, dec_p95, dec_std) = stats(dec_samples);

    println!("  Encapsulation key (ek):  1,184 bytes  (FIPS 203 §7.2)");
    println!("  Decapsulation key (dk):  2,400 bytes  (FIPS 203 §7.3)");
    println!("  Ciphertext (ct):         1,088 bytes  (FIPS 203 §7.4)");
    println!("  Shared secret (ss):         32 bytes");
    hr();
    println!(
        "  KeyGen:  med {:>7.3} ms  p95 {:>7.3} ms  +/-{:.4} ms",
        kg_med, kg_p95, kg_std
    );
    println!(
        "  Encaps:  med {:>7.3} ms  p95 {:>7.3} ms  +/-{:.4} ms",
        enc_med, enc_p95, enc_std
    );
    println!(
        "  Decaps:  med {:>7.3} ms  p95 {:>7.3} ms  +/-{:.4} ms",
        dec_med, dec_p95, dec_std
    );
}

// ── §5  ML-DSA-65 (FIPS 204) ─────────────────────────────────────────────────

fn bench_mldsa() {
    println!("\n=== ML-DSA-65 (FIPS 204) — Real Lattice Arithmetic (fips204 crate) ===");

    let message = b"LTP commitment record: entity_id=deadbeef root=cafebabe ts=1711670400";

    // Key generation
    for _ in 0..WARMUP {
        let _ = ml_dsa_65::try_keygen().unwrap();
    }
    let kg_samples: Vec<f64> = (0..MEDIUM_ITERS)
        .map(|_| {
            let t = Instant::now();
            let _ = ml_dsa_65::try_keygen().unwrap();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();

    let (vk, sk) = ml_dsa_65::try_keygen().unwrap();

    // Sign
    for _ in 0..WARMUP {
        let _ = sk.try_sign(message, b"").unwrap();
    }
    let sign_samples: Vec<f64> = (0..MEDIUM_ITERS)
        .map(|_| {
            let t = Instant::now();
            let _ = sk.try_sign(message, b"").unwrap();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();

    let sig = sk.try_sign(message, b"").unwrap();

    // Verify
    for _ in 0..WARMUP {
        let _ = vk.verify(message, &sig, b"");
    }
    let verify_samples: Vec<f64> = (0..FAST_ITERS)
        .map(|_| {
            let t = Instant::now();
            let _ = vk.verify(message, &sig, b"");
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();

    let (kg_med, kg_p95, kg_std) = stats(kg_samples);
    let (sign_med, sign_p95, sign_std) = stats(sign_samples);
    let (verify_med, verify_p95, verify_std) = stats(verify_samples);

    // Sizes via SerDes
    let vk_bytes = vk.clone().into_bytes().len();
    let sk_bytes = sk.clone().into_bytes().len();
    let sig_bytes = sig.len();

    println!("  Verification key (vk):  {:>5} bytes  (FIPS 204 §5.2)", vk_bytes);
    println!("  Signing key (sk):       {:>5} bytes  (FIPS 204 §5.1)", sk_bytes);
    println!("  Signature:              {:>5} bytes  (FIPS 204 §5.3)", sig_bytes);
    hr();
    println!(
        "  KeyGen:  med {:>7.3} ms  p95 {:>7.3} ms  +/-{:.4} ms",
        kg_med, kg_p95, kg_std
    );
    println!(
        "  Sign:    med {:>7.3} ms  p95 {:>7.3} ms  +/-{:.4} ms",
        sign_med, sign_p95, sign_std
    );
    println!(
        "  Verify:  med {:>7.3} ms  p95 {:>7.3} ms  +/-{:.4} ms",
        verify_med, verify_p95, verify_std
    );
}

// ── §6  LTP Lattice Key — Seal / Unseal ──────────────────────────────────────

fn bench_lattice_key() {
    println!("\n=== LTP Lattice Key -- Seal / Unseal ===");
    println!("  Seal:   ML-KEM-768 encaps  +  ChaCha20-Poly1305 encrypt(inner_payload)");
    println!("  Unseal: ML-KEM-768 decaps  +  ChaCha20-Poly1305 decrypt(inner_payload)");

    let (receiver_dk, receiver_ek) = MlKem768::generate_keypair();

    // Build a realistic inner payload (~195 bytes)
    let mut entity_id_bytes = [0u8; 16];
    let mut cek_bytes_arr = [0u8; 16];
    let mut ref_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut entity_id_bytes);
    OsRng.fill_bytes(&mut cek_bytes_arr);
    OsRng.fill_bytes(&mut ref_bytes);
    let inner_payload = format!(
        r#"{{"v":1,"entity_id":"{:032x}","cek":"{:032x}","commitment_ref":"{:032x}","policy":"unrestricted"}}"#,
        u128::from_le_bytes(entity_id_bytes),
        u128::from_le_bytes(cek_bytes_arr),
        u128::from_le_bytes(ref_bytes),
    )
    .into_bytes();

    let payload_len = inner_payload.len();

    // ── Seal benchmark
    for _ in 0..WARMUP {
        let (ct, ss) = receiver_ek.encapsulate();
        let key = Key::from_slice(ss.as_ref());
        let cipher = ChaCha20Poly1305::new(key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let _ = cipher.encrypt(&nonce, inner_payload.as_slice()).unwrap();
        let _ = ct;
    }
    let seal_samples: Vec<f64> = (0..MEDIUM_ITERS)
        .map(|_| {
            let t = Instant::now();
            let (ct, ss) = receiver_ek.encapsulate();
            let key = Key::from_slice(ss.as_ref());
            let cipher = ChaCha20Poly1305::new(key);
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let _ = cipher.encrypt(&nonce, inner_payload.as_slice()).unwrap();
            let _ = ct;
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();

    // Pre-seal once so unseal has something to work with
    let (pre_ct, pre_ss) = receiver_ek.encapsulate();
    let pre_key = Key::from_slice(pre_ss.as_ref());
    let pre_cipher = ChaCha20Poly1305::new(&pre_key);
    let pre_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let encrypted_payload = pre_cipher
        .encrypt(&pre_nonce, inner_payload.as_slice())
        .unwrap();

    // ── Unseal benchmark
    for _ in 0..WARMUP {
        let ss = receiver_dk.decapsulate(&pre_ct);
        let key = Key::from_slice(ss.as_ref());
        let cipher = ChaCha20Poly1305::new(key);
        let _ = cipher
            .decrypt(&pre_nonce, encrypted_payload.as_slice())
            .unwrap();
    }
    let unseal_samples: Vec<f64> = (0..MEDIUM_ITERS)
        .map(|_| {
            let t = Instant::now();
            let ss = receiver_dk.decapsulate(&pre_ct);
            let key = Key::from_slice(ss.as_ref());
            let cipher = ChaCha20Poly1305::new(key);
            let _ = cipher
                .decrypt(&pre_nonce, encrypted_payload.as_slice())
                .unwrap();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();

    let (seal_med, seal_p95, seal_std) = stats(seal_samples);
    let (unseal_med, unseal_p95, unseal_std) = stats(unseal_samples);

    // Wire format: KEM ct (1088B) + nonce (12B) + encrypted payload (includes 16B AEAD tag)
    let sealed_len = 1088 + 12 + encrypted_payload.len();

    println!("  Inner payload:  {:>5} bytes", payload_len);
    println!(
        "  Sealed key:     {:>5} bytes  (KEM ct: 1,088B + nonce: 12B + payload + tag: 16B)",
        sealed_len
    );
    hr();
    println!(
        "  Seal:    med {:>7.3} ms  p95 {:>7.3} ms  +/-{:.4} ms",
        seal_med, seal_p95, seal_std
    );
    println!(
        "  Unseal:  med {:>7.3} ms  p95 {:>7.3} ms  +/-{:.4} ms",
        unseal_med, unseal_p95, unseal_std
    );
}

// ── §7  End-to-End Protocol Phase Timings ────────────────────────────────────

fn bench_e2e() {
    println!("\n=== End-to-End Protocol Phase Timings ===");
    println!("  (n=8, k=4; production primitives; in-process, no network I/O)");
    println!();
    println!(
        "  {:>12}  {:>10}  {:>10}  {:>13}  {:>10}",
        "Entity size", "COMMIT", "LATTICE", "MATERIALIZE", "Key size"
    );
    hr();

    let rs = ReedSolomon::new(4, 4).unwrap();
    let (receiver_dk, receiver_ek) = MlKem768::generate_keypair();
    let (_, sk) = ml_dsa_65::try_keygen().unwrap();

    let sizes: &[(usize, &str)] = &[
        (1 << 10, "1.0 KB"),
        (10 << 10, "10.0 KB"),
        (100 << 10, "100.0 KB"),
        (1 << 20, "1.0 MB"),
    ];

    for &(size, label) in sizes {
        let shard_size = (size + 3) / 4;
        let mut entity = vec![0u8; size];
        OsRng.fill_bytes(&mut entity);

        // ── Phase 1: COMMIT
        let t_commit = Instant::now();

        let entity_id = blake3::hash(&entity);
        let shards = encode_shards(&rs, &entity, shard_size);

        let cek = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&cek);
        let encrypted_shards: Vec<(chacha20poly1305::Nonce, Vec<u8>)> = shards
            .iter()
            .map(|s| {
                let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
                let ct = cipher.encrypt(&nonce, s.as_ref()).unwrap();
                (nonce, ct)
            })
            .collect();

        // Commitment record: sign Merkle root (hash of all encrypted shard hashes)
        let merkle_input: Vec<u8> = encrypted_shards
            .iter()
            .flat_map(|(n, ct)| n.iter().chain(ct.iter()).copied())
            .collect();
        let merkle_root = blake3::hash(&merkle_input);
        let _sig = sk.try_sign(merkle_root.as_bytes(), b"").unwrap();

        let commit_ms = t_commit.elapsed().as_secs_f64() * 1000.0;

        // ── Phase 2: LATTICE
        let t_lattice = Instant::now();

        let cek_hex: String = cek.iter().map(|b| format!("{:02x}", b)).collect();
        let payload = format!(
            r#"{{"v":1,"entity_id":"{}","cek":"{}","policy":"unrestricted"}}"#,
            entity_id, cek_hex
        )
        .into_bytes();

        let (lat_ct, lat_ss) = receiver_ek.encapsulate();
        let lat_key = Key::from_slice(lat_ss.as_ref());
        let lat_cipher = ChaCha20Poly1305::new(&lat_key);
        let lat_nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let encrypted_payload = lat_cipher
            .encrypt(&lat_nonce, payload.as_slice())
            .unwrap();

        let sealed_len = 1088 + 12 + encrypted_payload.len();

        let lattice_ms = t_lattice.elapsed().as_secs_f64() * 1000.0;

        // ── Phase 3: MATERIALIZE
        let t_mat = Instant::now();

        // Unseal lattice key
        let recv_ss = receiver_dk.decapsulate(&lat_ct);
        let recv_key = Key::from_slice(recv_ss.as_ref());
        let recv_cipher = ChaCha20Poly1305::new(&recv_key);
        let _recv_payload = recv_cipher
            .decrypt(&lat_nonce, encrypted_payload.as_slice())
            .unwrap();

        // Fetch k=4 shards and decrypt
        let plaintext_shards: Vec<Vec<u8>> = encrypted_shards[..4]
            .iter()
            .map(|(nonce, ct)| cipher.decrypt(nonce, ct.as_ref()).unwrap())
            .collect();

        // Reconstruct entity
        let reconstructed: Vec<u8> = plaintext_shards
            .iter()
            .flat_map(|s| s.iter().copied())
            .take(size)
            .collect();

        // Verify content hash
        let recomputed_id = blake3::hash(&reconstructed);
        assert_eq!(
            entity_id.as_bytes(),
            recomputed_id.as_bytes(),
            "content hash mismatch"
        );

        let mat_ms = t_mat.elapsed().as_secs_f64() * 1000.0;

        println!(
            "  {:>12}  {:>7.1} ms  {:>7.1} ms  {:>10.1} ms  {:>8} B",
            label, commit_ms, lattice_ms, mat_ms, sealed_len,
        );
    }

    println!();
    println!("  COMMIT       = BLAKE3 hash + RS encode + AEAD encrypt x8 + ML-DSA sign");
    println!("  LATTICE      = ML-KEM encaps + AEAD encrypt(inner_payload) [O(1) in entity size]");
    println!("  MATERIALIZE  = ML-KEM decaps + AEAD decrypt x4 + BLAKE3 verify");
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() {
    println!("LTP Production Rust Benchmark");
    println!("==========================================================");
    println!("Platform: {}", std::env::consts::OS);
    println!("Arch:     {}", std::env::consts::ARCH);
    println!();
    println!("Libraries (real implementations -- no PoC simulations):");
    println!("  blake3               v1.x        -- BLAKE3-256 content addressing");
    println!("  chacha20poly1305     v0.10        -- ChaCha20-Poly1305 AEAD");
    println!("  reed-solomon-erasure v6           -- GF(256) RS erasure coding");
    println!("  ml-kem               v0.3.0-rc.1  -- ML-KEM-768 (FIPS 203)");
    println!("  fips204              v0.4         -- ML-DSA-65 (FIPS 204)");
    println!();
    println!("Statistics: median (p50) / p95 / sample stddev");
    println!("Warmup:    {} iterations discarded before measurement", WARMUP);

    bench_blake3();
    bench_aead();
    bench_rs();
    bench_mlkem();
    bench_mldsa();
    bench_lattice_key();
    bench_e2e();

    println!();
    println!("==========================================================");
    println!("Benchmark complete.");
}
