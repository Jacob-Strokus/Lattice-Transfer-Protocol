LTP Production Rust Benchmark — Results
==========================================================
Platform: windows
Arch:     x86_64 (Intel Core i7-8700)
Rustc:    1.94.1 (2026-03-25), release profile (opt-level=3, LTO, codegen-units=1)
Date:     2026-03-29

Libraries (real implementations — no PoC simulations):
  blake3               v1.x        — BLAKE3-256 content addressing
  chacha20poly1305     v0.10       — ChaCha20-Poly1305 AEAD
  reed-solomon-erasure v6          — GF(256) RS erasure coding
  ml-kem               v0.3.0-rc.1 — ML-KEM-768 (FIPS 203)
  fips204              v0.4        — ML-DSA-65 (FIPS 204)

Statistics: median (p50) / p95 / sample stddev
Warmup:    5 iterations discarded before measurement

=== BLAKE3-256 Hash Throughput ===
      1.0 KB    0.001 ms    p95 0.001 ms  ±0.000 ms    1,220.7 MB/s
     64.0 KB    0.013 ms    p95 0.013 ms  ±0.000 ms    4,845.0 MB/s
      1.0 MB    0.212 ms    p95 0.269 ms  ±0.017 ms    4,725.9 MB/s
     10.0 MB    2.202 ms    p95 2.663 ms  ±0.211 ms    4,541.4 MB/s

=== AEAD ChaCha20-Poly1305 Encrypt / Decrypt Throughput ===
      1.0 KB  enc   0.002 ms ±0.000 (  574.4 MB/s)  dec   0.002 ms ±0.000 (  542.5 MB/s)
     64.0 KB  enc   0.035 ms ±0.002 (1,785.7 MB/s)  dec   0.035 ms ±0.002 (1,780.6 MB/s)
      1.0 MB  enc   0.711 ms ±0.011 (1,405.9 MB/s)  dec   0.683 ms ±0.039 (1,463.3 MB/s)

=== Reed-Solomon Erasure Coding RS(n=8, k=4) over GF(256) ===
      1.0 KB  -> 8 x    256B  enc   0.002 ms ±0.000 (406.9 MB/s)  dec   0.002 ms ±0.000 (488.3 MB/s)
     64.0 KB  -> 8 x  16384B  enc   0.117 ms ±0.001 (534.0 MB/s)  dec   0.114 ms ±0.001 (548.5 MB/s)
      1.0 MB  -> 8 x 262144B  enc   1.625 ms ±0.012 (615.2 MB/s)  dec   1.790 ms ±0.071 (558.7 MB/s)

=== ML-KEM-768 (FIPS 203) — Key Sizes & Operations ===
  Encapsulation key (ek):  1,184 bytes
  Decapsulation key (dk):  2,400 bytes
  Ciphertext (ct):         1,088 bytes
  Shared secret (ss):         32 bytes

  KeyGen:  med   0.044 ms  p95   0.046 ms  ±0.0007 ms
  Encaps:  med   0.042 ms  p95   0.042 ms  ±0.0010 ms
  Decaps:  med   0.054 ms  p95   0.057 ms  ±0.0016 ms

=== ML-DSA-65 (FIPS 204) — Key Sizes & Operations ===
  Verification key (vk):   1,952 bytes
  Signing key (sk):        4,032 bytes
  Signature:               3,309 bytes

  KeyGen:  med   0.194 ms  p95   0.200 ms  ±0.0091 ms
  Sign:    med   0.387 ms  p95   1.211 ms  ±0.3155 ms
  Verify:  med   0.131 ms  p95   0.133 ms  ±0.0019 ms

=== LTP Lattice Key Sizes & Seal / Unseal ===
  Seal:   ML-KEM-768 encaps + ChaCha20-Poly1305 encrypt(inner_payload)
  Unseal: ML-KEM-768 decaps + ChaCha20-Poly1305 decrypt(inner_payload)

  Inner payload:    171 bytes
  Sealed key:     1,287 bytes  (KEM ct: 1,088B + nonce: 12B + payload + tag: 16B)

  Seal:    med   0.044 ms  p95   0.044 ms  ±0.0003 ms
  Unseal:  med   0.056 ms  p95   0.057 ms  ±0.0004 ms

=== End-to-End Protocol Phase Timings ===
  (n=8, k=4; production primitives; in-process, no network I/O)

   Entity size      COMMIT     LATTICE    MATERIALIZE    Key size
  ---------------------------------------------------------------
        1.0 KB      0.3 ms      0.1 ms         0.1 ms    1,299 B
       10.0 KB      0.3 ms      0.1 ms         0.1 ms    1,299 B
      100.0 KB      1.6 ms      0.1 ms         0.3 ms    1,299 B
        1.0 MB      6.1 ms      0.1 ms         2.4 ms    1,299 B

  COMMIT       = BLAKE3 hash + RS encode + AEAD encrypt x8 + ML-DSA sign
  LATTICE      = ML-KEM encaps + AEAD encrypt(inner_payload)  [O(1) in entity size]
  MATERIALIZE  = ML-KEM decaps + AEAD decrypt x4 + BLAKE3 verify

=== Python PoC vs Rust Production — Speed Comparison ===
  (Same hardware, same workload; Python = BLAKE2b PoC simulations + pure-Python RS)

  Operation            Python PoC      Rust (prod)   Speedup
  ------------------------------------------------------------
  Hash 64 KB           890.8 MB/s    4,845.0 MB/s     5.4x
  AEAD enc 64 KB        18.1 MB/s    1,785.7 MB/s    98.6x
  RS encode 1 MB         0.5 MB/s      615.2 MB/s  ~1,230x
  RS decode 1 MB         1.4 MB/s      558.7 MB/s    ~399x
  ML-KEM encaps*        0.076 ms       0.042 ms       1.8x
  ML-DSA sign*          0.061 ms       0.387 ms   real math
  Seal lattice key*     0.104 ms       0.044 ms       2.4x
  E2E COMMIT 1 MB     2,327 ms          6.1 ms      382x
  E2E MATERIALIZE 1MB   853 ms          2.4 ms      355x

  * Python ML-KEM/DSA are BLAKE2b simulations with correct key sizes but no
    lattice math. Rust uses real FIPS 203/204 implementations. The ML-DSA sign
    latency is higher in Rust (0.387ms vs 0.061ms) because it does actual
    lattice-based signing, not a hash. This is the correct production cost.
