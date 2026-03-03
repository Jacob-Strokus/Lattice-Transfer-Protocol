# LTP: Lattice Transfer Protocol — Whitepaper

**Version:** 0.1.0-draft  
**Date:** 2026-02-24  
**Status:** Exploratory Design

---

### Note on Terminology

The name **"Lattice"** is deliberately chosen for its triple resonance with the protocol's design:

1. **Network lattice** — the distributed commitment nodes form a lattice topology through which
   shards are placed, replicated, and fetched from the nearest points
2. **Lattice-based cryptography** — the protocol's post-quantum primitives (ML-KEM-768 and
   ML-DSA-65) are founded on the hardness of the Module Learning With Errors problem, a
   lattice problem in algebraic number theory
3. **Mathematical lattice** — the erasure-coded shard space forms a partially ordered structure
   where any k-of-n subset is sufficient for reconstruction

The name does **not** imply any connection to quantum entanglement, quantum mechanics, or
quantum information theory. The protocol operates entirely within classical computing and
post-quantum cryptography.

---

## Abstract

We propose a data transfer protocol in which no data payload is transmitted between sender and
receiver. Instead, the sender **commits** an immutable, content-addressed representation of the
entity to a distributed commitment layer, transmits a minimal cryptographic **lattice key**
to the receiver, and the receiver **materializes** the entity through deterministic reconstruction
from distributed shards. The protocol achieves:

- **Decoupled transfer** — the sender→receiver path carries only a ~1,300-byte sealed key (ML-KEM-768), independent of entity size. Total system bandwidth is O(entity × replication), but the direct-path bottleneck is eliminated.
- **Immutability by design** — every transfer is a permanent, auditable commitment
- **Security without trust** — verification is mathematical, not institutional
- **Geography-optimized materialization** — the receiver fetches shards from the nearest available nodes, converting a long-haul transfer into parallel local fetches

---

## 1. The Ontology of Data Transfer

### 1.1 What Is an "Entity"?

In LTP, we do not transfer "files," "packets," or "messages." We transfer **entities**. An entity
is any discrete, self-contained unit of state:

- A document
- A database row
- A video frame sequence
- A machine learning model
- An application state snapshot
- A human identity credential

An entity has three properties:
1. **Content** — the raw information
2. **Shape** — the schema/structure that gives content meaning
3. **Identity** — a unique, deterministic fingerprint derived from content + shape

### 1.2 The Entity Identity Function

Every entity has a deterministic identity:

```
EntityID = H(content || shape || timestamp || sender_pubkey)
```

Where:
- `H` is a collision-resistant hash function (e.g., BLAKE3 or Poseidon for ZK-friendliness)
- `||` denotes concatenation
- `timestamp` is the commitment time (logical clock, not wall clock)
- `sender_pubkey` is the sender's public key, binding identity to origin

This identity is **permanent**. The same content committed by the same sender at the same
logical moment always produces the same identity. Different moment = different entity. This
is not a bug — it is the immutability guarantee.

---

## 2. The Three Phases of Transfer

### Phase 1: COMMIT

The sender does not prepare the entity for transmission. Instead, the sender **commits** the
entity to a distributed commitment layer.

#### 2.1.1 Deterministic Sharding

The entity is decomposed into `n` shards using deterministic erasure coding,
then each shard is encrypted with a random Content Encryption Key (CEK):

```
plaintext_shards = ErasureEncode(entity, n, k)
CEK = CSPRNG(256 bits)     # MUST be fresh per entity — see invariant below
encrypted_shards = [AEAD_Encrypt(CEK, shard, nonce=index) for index, shard in enumerate(plaintext_shards)]
```

Where:
- `n` = total number of shards produced
- `k` = minimum number of shards needed to reconstruct (k < n)
- The encoding is deterministic: same input always produces same shards
- `CEK` = a random 256-bit Content Encryption Key, unique per entity
- Each shard is encrypted with AEAD (authenticated encryption) before distribution
- Commitment nodes store **only ciphertext** — they cannot read shard content
- Each encrypted shard is integrity-checked: `ShardHash = H(encrypted_shard || entity_id || shard_index)`

**Security Invariant — CEK Uniqueness (Nonce Safety):**

Each shard's AEAD nonce is deterministically derived from its shard index (`nonce = index`).
This means the nonce domain is small and predictable. The scheme is safe because each
(CEK, nonce) pair is used exactly once — guaranteed by the requirement that every entity
receives a fresh, independently random CEK from a CSPRNG (e.g., `os.urandom`, `/dev/urandom`,
`CryptGenRandom`).

**CEK reuse across entities is a catastrophic failure mode.** If two entities share the same
CEK, their corresponding shards (at the same index) are encrypted with identical (key, nonce)
pairs. For XOR-based stream ciphers (and most AEAD constructions), this enables plaintext
recovery via crib-dragging:

$$c_1 \oplus c_2 = (p_1 \oplus \text{keystream}) \oplus (p_2 \oplus \text{keystream}) = p_1 \oplus p_2$$

This invariant MUST hold even if the protocol evolves to support entity updates or
re-commitment: each commit operation MUST generate a fresh CEK regardless of whether the
content or entity_id has been seen before. Implementations SHOULD validate that the CEK is
not degenerate (all-zero, all-one) and SHOULD track issued CEKs within a process as a
defense-in-depth measure.

#### 2.1.2 Distributed Shard Placement

Shards are placed across a distributed network of **commitment nodes**. Placement follows a
deterministic algorithm based on the EntityID:

```
placement(shard_i) = ConsistentHash(EntityID || shard_index) → node_set
```

This means:
- Both sender and receiver can independently compute where shards live
- No central registry or lookup service is needed
- Shards are replicated across geographically diverse nodes
- The receiver will materialize from the **nearest** available shards

#### 2.1.3 The Commitment Record

Once shards are distributed, the sender publishes a **commitment record** to an append-only
commitment log (this can be a blockchain, a Merkle DAG, or any immutable append-only structure):

```json
{
  "entity_id": "blake3:7f3a8b...",
  "sender": "ml-dsa-65:verification_key...",
  "shard_map_root": "blake3:merkle_root_of_encrypted_shard_hashes",
  "encoding_params": { "n": 64, "k": 32, "algorithm": "reed-solomon-gf256" },
  "shape_hash": "blake3:schema_hash...",
  "timestamp": 1740422400,
  "signature": "ml-dsa-65:sig...  (3,309 bytes, quantum-resistant)"
}
```

Critical security property: the commitment record contains **no individual shard IDs**.
Only a Merkle root of hashes of **encrypted** shards is stored. This reveals nothing
about the plaintext content — they are hashes of ciphertext.

The record is the **proof that the entity exists and was committed**. It is small (< 1 KB),
immutable, and independently verifiable.

### Phase 2: LATTICE

The sender transmits a minimal **lattice key** to the receiver. This is the only data
that traverses the sender → receiver path directly.

#### 2.2.1 The Lattice Key

The lattice key contains exactly **three secrets** and a policy:

```
LatticeKey = {
  entity_id,              // 32 bytes — which entity to materialize
  content_encryption_key, // 32 bytes — CEK to decrypt shards
  commitment_ref,         // 32 bytes — hash of commitment record
  access_policy           // ~20-50 bytes — materialization rules
}
```

Critically, the key does **NOT** contain:
- `shard_ids` — receiver derives shard locations from `entity_id` via consistent hashing
- `encoding_params` — receiver reads these from the commitment record
- `sender_id` — receiver reads this from the commitment record

The entire key is **sealed** via ML-KEM-768 (FIPS 203) key encapsulation. Each seal
operation generates a fresh encapsulation, providing forward secrecy per transfer.

The lattice key is:
- **Minimal** — ~160 bytes inner payload, ~1,300 bytes sealed, regardless of entity size
- **Sealed** — ML-KEM encapsulated to the receiver's encapsulation key (quantum-resistant)
- **Self-authenticating** — contains the commitment reference for verification
- **Policy-bound** — includes access rules (one-time, time-limited, delegatable, etc.)
- **Opaque** — an interceptor sees only random bytes (no metadata leaks)
- **Post-quantum** — ML-KEM-768 resists both classical and quantum adversaries

#### 2.2.2 Key Properties of Latticement

The lattice key is **not the data**. It is the **proof of right to reconstruct**. This
creates several remarkable properties:

1. **Sender→receiver decoupling**: Transferring 1 KB and transferring 1 TB produce the same
   size sealed lattice key (~1,300 bytes). The sender→receiver direct transmission is O(1).
   Note: total system bandwidth is O(entity × replication) across the commit and materialize
   phases. The advantage is not bandwidth elimination — it is *bottleneck relocation*: the
   sender-receiver path (often the slowest link) is reduced to a constant, and the O(entity)
   work shifts to the receiver↔network path, which can be geographically optimized.

2. **Three-layer interception resistance**: An attacker faces three independent barriers:
   - **Layer 1 (Sealed envelope)**: The key is encrypted to the receiver's public key;
     intercepting it yields opaque ciphertext with no metadata
   - **Layer 2 (Encrypted shards)**: Even if an attacker queries the commitment network
     directly, all shards are AEAD-encrypted; without the CEK, they are useless
   - **Layer 3 (Minimal log)**: The commitment log contains only a Merkle root of
     ciphertext hashes — no individual shard IDs, no content, no CEK

3. **Non-repudiation**: The commitment record on the append-only log proves the sender committed
   the entity. The lattice key proves the sender authorized the receiver. Both are
   cryptographically signed.

4. **Forward secrecy**: Each lattice key uses a fresh ML-KEM-768 encapsulation, producing
   a unique (shared_secret, ciphertext) pair per seal. The shared_secret is used once for AEAD
   encryption and then immediately zeroized. Compromising the receiver's decapsulation key
   after the shared_secret has been destroyed does not expose historical transfers.

   **Forward secrecy lifecycle:**
   1. `seal()` calls ML-KEM.Encaps(receiver_ek) → fresh (ss, kem_ct)
   2. ss is used as the AEAD key for the payload, then zeroized in memory
   3. kem_ct is embedded in the sealed output
   4. Only the holder of dk can recover ss from kem_ct (Module-LWE hardness)
   5. After the receiver processes the sealed key and zeroizes ss, the shared
      secret is unrecoverable — even if dk is later compromised
   6. For defense-in-depth, receivers SHOULD rotate ek/dk periodically;
      old dk values MUST be securely destroyed after rotation

### Phase 3: MATERIALIZE

The receiver uses the lattice key to **reconstruct** the entity from the commitment layer.

#### 2.3.1 Reconstruction Process

```
1. Unseal lattice key with receiver's private key → extract entity_id, CEK, commitment_ref
2. Fetch commitment record from append-only log using entity_id
3. Verify commitment record: H(record) == commitment_ref (integrity check)
4. Verify commitment record signature (sender authenticity)
5. Read encoding params (n, k) from commitment record
6. Derive shard locations: ConsistentHash(entity_id || shard_index) for index in 0..n-1
7. Fetch k-of-n ENCRYPTED shards from nearest available commitment nodes (parallel)
8. Decrypt each shard: AEAD_Decrypt(CEK, encrypted_shard, nonce=shard_index)
   — AEAD authentication tag is verified BEFORE decryption (tamper detection)
9. ErasureDecode(decrypted_shards, k) → entity content
10. Verify: H(entity_content || shape || timestamp || sender_pubkey) == entity_id
11. Entity materialized. Transfer complete.
```

#### 2.3.2 Why This Is Fast

Traditional transfer: **move all the data across one path (sender → receiver)**

LTP materialization: **pull k shards in parallel from the nearest nodes in the commitment network**

```
Traditional:    S ════════════════(entire payload)════════════════> R
                  Bottleneck: sender upload × distance to receiver

LTP:            S ──(~1,300B sealed key)──> R
                                          R <── encrypted shard from nearby Node
                                          R <── encrypted shard from nearby Node
                                          R <── encrypted shard from nearby Node
                                          R <── encrypted shard from nearby Node
                                          ...k shards, parallel, nearest-first
```

**Important nuance:** The total bytes moved across the system is *greater* than direct
transfer — the commit phase uploads O(entity × replication_factor) to the network, and the
materialize phase downloads O(entity) from it. LTP does not eliminate bandwidth; it
**relocates the bottleneck**:

- The sender→receiver path (often the slowest, highest-latency link) shrinks to O(1)
- The O(entity) work shifts to receiver↔nearby-nodes, which can be geographically local
- The commit-phase bandwidth is amortized: committed once, materialized by many receivers

The win is not "less bandwidth" — it is **faster perceived transfer** via parallelism,
geographic locality, and sender-independence. For fan-out scenarios (one sender, many
receivers), the amortized cost approaches O(entity) total regardless of receiver count,
whereas direct transfer costs O(entity × receiver_count).

---

## 3. Security Model

### 3.1 Threat Analysis

| Threat | Mitigation |
|--------|-----------|
| Man-in-the-middle intercepts lattice key | Entire key is sealed (envelope-encrypted) to receiver's public key; interceptor sees opaque ciphertext with zero metadata |
| Attacker scrapes commitment log | Log contains only Merkle root of encrypted shard hashes — no shard IDs, no content, no CEK |
| Attacker fetches shards from nodes | Shards are AEAD-encrypted with CEK; without CEK, ciphertext is computationally useless |
| Attacker compromises < k nodes | Information-theoretic security: < k shards (even decrypted) reveal zero information about the entity |
| Sender denies transfer occurred | Commitment record is on immutable append-only log with sender's signature |
| Receiver claims different data was sent | Entity ID is deterministic hash of content; both parties can verify |
| Replay attack (re-use lattice key) | Access policy can enforce one-time materialization; commitment nodes track access |
| Quantum computing threat | **Full post-quantum security**: ML-KEM-768 (FIPS 203) for key encapsulation, ML-DSA-65 (FIPS 204) for signatures, BLAKE2b/BLAKE3 for hashing (quantum-resistant), erasure coding is information-theoretic (quantum-immune). No X25519 or Ed25519 in the protocol. |

### 3.2 Zero-Knowledge Transfer Mode

For maximum privacy, LTP supports a zero-knowledge variant where:

1. The commitment record is encrypted; only the entity_id is public
2. Shard content is encrypted with a key derived from the entity_id + sender's secret
3. The receiver's lattice key includes the decryption material
4. Commitment nodes store shards but **cannot read them**
5. A ZK-proof accompanies the commitment record proving the entity satisfies certain properties
   (e.g., "this is a valid JSON document" or "this number is in range [0, 1000]") without
   revealing the content

```
CommitmentRecord + ZK-Proof: "I committed a valid entity. Here's the proof. You can verify
without seeing the data."
```

### 3.3 Formal Security Definitions

This section defines the security properties of LTP as cryptographic games and formally
reduces each to standard assumptions. We adopt the notation of Bellare and Rogaway:
$\mathcal{A}$ denotes a PPT (probabilistic polynomial time) adversary, $\mathsf{negl}(\lambda)$
denotes a negligible function in security parameter $\lambda$, and $\mathsf{Adv}^{X}_{\mathcal{A}}$
denotes $\mathcal{A}$'s advantage in game $X$.

#### 3.3.1 Entity Immutability (Collision Resistance)

**Definition (IMM game).** The immutability game $\mathsf{Game}_{\mathcal{A}}^{\text{IMM}}$
proceeds as follows:

```
Game IMM:
  1. Adversary A receives the hash function H and the protocol parameters.
  2. A outputs two entities (e, e') with e ≠ e'.
  3. A wins if EntityID(e) = EntityID(e').
```

**Theorem 3 (Entity Immutability).** For any PPT adversary $\mathcal{A}$:

$$\mathsf{Adv}^{\text{IMM}}_{\mathcal{A}}(\lambda) \leq \mathsf{Adv}^{\text{CR}}_{H}(\lambda)$$

where $\mathsf{Adv}^{\text{CR}}_{H}$ is the collision-resistance advantage against $H$
(BLAKE2b-256).

*Proof.* Reduction: Given $\mathcal{A}$ that wins IMM, construct $\mathcal{B}$ that breaks
collision resistance of $H$. $\mathcal{B}$ runs $\mathcal{A}$ and receives $(e, e')$ with
$e \neq e'$ and $H(\text{encode}(e)) = H(\text{encode}(e'))$. Since $e \neq e'$ implies
$\text{encode}(e) \neq \text{encode}(e')$ (encoding is injective), $\mathcal{B}$ outputs
$(\text{encode}(e), \text{encode}(e'))$ as a collision for $H$. ∎

**Concrete security.** For BLAKE2b-256 ($n = 256$ output bits), the birthday bound gives
$\mathsf{Adv}^{\text{CR}}_{H} \leq q^2 / 2^{257}$ where $q$ is the number of hash
evaluations. At $q = 2^{128}$ (computational limit): $\mathsf{Adv} \approx 2^{-1}$
(infeasible in practice). Grover's algorithm reduces preimage search to $O(2^{128})$
quantum queries but does **not** improve the birthday bound for collisions.

#### 3.3.2 Shard Integrity (Second-Preimage Resistance)

**Definition (SINT game).** The shard integrity game $\mathsf{Game}_{\mathcal{A}}^{\text{SINT}}$
proceeds as follows:

```
Game SINT:
  1. Challenger commits entity e with shards {s_0, ..., s_{n-1}}.
  2. Adversary A receives entity_id, all shard hashes H(s_i ‖ entity_id ‖ i),
     and the AEAD ciphertexts (as stored on commitment nodes).
  3. A outputs (i, s_i') with s_i' ≠ s_i.
  4. A wins if H(s_i' ‖ entity_id ‖ i) = H(s_i ‖ entity_id ‖ i)
     AND the AEAD tag verifies.
```

**Theorem 4 (Shard Integrity).** For any PPT adversary $\mathcal{A}$:

$$\mathsf{Adv}^{\text{SINT}}_{\mathcal{A}}(\lambda) \leq \mathsf{Adv}^{\text{SPR}}_{H}(\lambda) + \mathsf{Adv}^{\text{AUTH}}_{\text{AEAD}}(\lambda)$$

where $\mathsf{Adv}^{\text{SPR}}_{H}$ is the second-preimage resistance advantage and
$\mathsf{Adv}^{\text{AUTH}}_{\text{AEAD}}$ is the AEAD authentication advantage.

*Proof.* $\mathcal{A}$ must either: (a) find $s_i'$ that collides in $H$ (breaking SPR), or
(b) forge an AEAD ciphertext that decrypts to $s_i' \neq s_i$ (breaking AEAD authenticity).
These are independent events; the advantage is bounded by their sum. ∎

**Note (double protection).** Even without AEAD, content-addressing catches substitution.
AEAD adds a second layer: the AEAD tag authenticates each shard independently, so a
compromised commitment node cannot serve a modified shard that passes decryption. Both
layers must be defeated simultaneously.

#### 3.3.3 Transfer Confidentiality (IND-CPA)

**Definition (TCONF game).** Transfer confidentiality is defined via an IND-CPA-style
indistinguishability game adapted for LTP's commit-lattice-materialize structure:

```
Game TCONF:
  1. Challenger generates keypairs for sender S and receiver R.
  2. Adversary A chooses two equal-length entities (e_0, e_1) and submits them.
  3. Challenger flips coin b ∈ {0, 1} and runs the full LTP protocol on e_b:
     - COMMIT: erasure encode, AEAD encrypt shards, distribute to nodes
     - LATTICE: seal key to R's public key
  4. Adversary A receives:
     - The sealed lattice key (ML-KEM ciphertext)
     - All encrypted shards stored on commitment nodes
     - The commitment record (entity_id, Merkle root, encoding params, ML-DSA signature)
  5. A outputs guess b'.
  6. A wins if b' = b.
```

**Theorem 5 (Transfer Confidentiality).** For any PPT adversary $\mathcal{A}$:

$$\mathsf{Adv}^{\text{TCONF}}_{\mathcal{A}}(\lambda) \leq 2 \cdot \mathsf{Adv}^{\text{IND-CCA}}_{\text{ML-KEM}}(\lambda) + \mathsf{Adv}^{\text{IND-CPA}}_{\text{AEAD}}(\lambda) + \mathsf{Adv}^{\text{PRF}}_{\text{CEK-KDF}}(\lambda)$$

*Proof sketch.* We proceed via a sequence of games:

- **Game 0** = TCONF. The adversary sees sealed key + encrypted shards + log entry.
- **Game 1**: Replace ML-KEM shared secret with random. By ML-KEM IND-CCA security,
  $|\Pr[G_0] - \Pr[G_1]| \leq \mathsf{Adv}^{\text{IND-CCA}}_{\text{ML-KEM}}$.
  Now the sealed key is a random encryption — independent of $b$.
- **Game 2**: Replace AEAD encryptions of shards with encryptions of zeros. By AEAD
  IND-CPA security, $|\Pr[G_1] - \Pr[G_2]| \leq \mathsf{Adv}^{\text{IND-CPA}}_{\text{AEAD}}$.
  Now the shard ciphertexts are independent of $b$.
- **Game 3**: Replace the EntityID with a random value. The EntityID is $H(e_b)$; since
  shards are already independent of $b$ (Game 2), and the Merkle root is over encrypted
  shard hashes (also independent of $b$), the only remaining leakage is the EntityID
  itself. Under the PRF assumption on the hash (or in the random oracle model):
  $|\Pr[G_2] - \Pr[G_3]| \leq \mathsf{Adv}^{\text{PRF}}_{\text{CEK-KDF}}$.

In Game 3 the adversary's view is independent of $b$, so $\Pr[G_3] = 1/2$. ∎

**Important caveat.** The EntityID is a deterministic function of content. If the adversary
can enumerate possible entities (e.g., "yes" or "no"), the EntityID acts as a fingerprint.
This is inherent to content-addressed systems and shared with IPFS, Git, etc. The ZK
transfer mode (§3.2) mitigates this by encrypting the commitment record.

#### 3.3.4 Commitment Non-Repudiation (EUF-CMA)

**Definition (NREP game).** The non-repudiation game $\mathsf{Game}_{\mathcal{A}}^{\text{NREP}}$
proceeds as follows:

```
Game NREP:
  1. Challenger generates ML-DSA-65 keypair (vk, sk) for sender S.
  2. Adversary A is given vk and oracle access to Sign(sk, ·).
  3. A outputs a commitment record c* and signature σ* such that:
     - Verify(vk, c*, σ*) = ACCEPT
     - S never signed c* (c* was not queried to the signing oracle)
  4. A wins if the above conditions hold.
```

**Theorem 6 (Non-Repudiation).** For any PPT adversary $\mathcal{A}$:

$$\mathsf{Adv}^{\text{NREP}}_{\mathcal{A}}(\lambda) \leq \mathsf{Adv}^{\text{EUF-CMA}}_{\text{ML-DSA-65}}(\lambda)$$

*Proof.* Direct reduction: $\mathcal{B}$ embeds the EUF-CMA challenge key as $S$'s
verification key. Any forgery $(c^*, \sigma^*)$ from $\mathcal{A}$ is a valid EUF-CMA
forgery. ML-DSA-65 (FIPS 204) achieves NIST Level 3 security (128 bits against quantum
adversaries via the Module-LWE hardness assumption). ∎

**Consequence.** Once a sender commits an entity and the ML-DSA-65 signature is recorded in
the append-only log, the sender cannot deny the commitment. The receiver can present the
signed record as unforgeable evidence of the transfer's existence.

#### 3.3.5 Threshold Secrecy (Information-Theoretic)

**Definition (TSEC game).** The threshold secrecy game
$\mathsf{Game}_{\mathcal{A}}^{\text{TSEC}}$ proceeds as follows:

```
Game TSEC:
  1. Adversary A chooses two messages (m_0, m_1) of equal length.
  2. Challenger flips coin b ∈ {0, 1}, erasure-encodes m_b into n shards.
  3. A receives any t < k shards of her choice (adaptive or non-adaptive).
  4. A outputs guess b'.
  5. A wins if b' = b.
```

**Theorem 7 (Threshold Secrecy).** For any adversary $\mathcal{A}$ (computationally unbounded):

$$\mathsf{Adv}^{\text{TSEC}}_{\mathcal{A}} = 0 \quad \text{for } t < k$$

*Proof.* The Vandermonde encoding evaluates a degree-$(k-1)$ polynomial $p(x) = \sum_{j=0}^{k-1} c_j x^j$
over GF(256) at $n$ distinct points. Any $t < k$ evaluations leave $k - t \geq 1$ degrees
of freedom. For every candidate message $m$, there exists a unique polynomial consistent
with the observed shards. Therefore:

$$\Pr[M = m_b \mid \text{any } t < k \text{ shards}] = \Pr[M = m_b]$$

This is a **perfect secrecy** (Shannon-sense) result — it holds against adversaries with
unlimited computational power, including quantum computers. It is the MDS (Maximum Distance
Separable) property of Reed-Solomon codes. ∎

**In LTP's context:** Even if an adversary compromises $k - 1$ commitment nodes and decrypts 
the AEAD ciphertexts (by also obtaining the CEK), the $k - 1$ plaintext shards reveal zero 
information about the entity. Information-theoretic secrecy provides a second line of defense
behind AEAD encryption.

#### 3.3.6 Transfer Immutability (Composite Game)

**Definition (TIMM game).** Transfer immutability captures the end-to-end property: no
adversary can cause a receiver to accept an entity different from what the sender committed.
This is the defining security goal of LTP.

```
Game TIMM:
  1. Challenger runs honest setup: generates keypairs, commitment network.
  2. Sender S commits entity e via COMMIT, producing record R and CEK.
  3. S creates lattice key K via LATTICE, sealed to receiver R's pk.
  4. Adversary A controls the network: A can modify, drop, or inject
     shards on commitment nodes; A can modify the sealed key in transit;
     A can forge commitment records (if able); A controls all nodes
     except the append-only log.
  5. Receiver R runs MATERIALIZE with whatever A delivers.
  6. A wins if R outputs e' with e' ≠ e (receiver accepts wrong data).
```

**Theorem 8 (Transfer Immutability).** For any PPT adversary $\mathcal{A}$:

$$\mathsf{Adv}^{\text{TIMM}}_{\mathcal{A}}(\lambda) \leq \mathsf{Adv}^{\text{CR}}_{H}(\lambda) + \mathsf{Adv}^{\text{EUF-CMA}}_{\text{ML-DSA}}(\lambda) + \mathsf{Adv}^{\text{AUTH}}_{\text{AEAD}}(\lambda) + \mathsf{Adv}^{\text{IND-CCA}}_{\text{ML-KEM}}(\lambda)$$

*Proof.* The adversary must defeat at least one of four barriers:

1. **Unseal the lattice key** to learn the CEK and entity_id → requires breaking ML-KEM
   IND-CCA ($\mathsf{Adv}^{\text{IND-CCA}}_{\text{ML-KEM}}$).

2. **Forge the commitment record** to point to a different Merkle root → requires breaking
   ML-DSA EUF-CMA ($\mathsf{Adv}^{\text{EUF-CMA}}_{\text{ML-DSA}}$).

3. **Substitute shard ciphertexts** that decrypt to different plaintext shards → requires
   breaking AEAD authenticity ($\mathsf{Adv}^{\text{AUTH}}_{\text{AEAD}}$).

4. **Find a different entity $e'$** with $H(e') = H(e)$ that passes the final integrity
   check → requires breaking collision resistance of $H$
   ($\mathsf{Adv}^{\text{CR}}_{H}$).

Since the receiver's MATERIALIZE phase verifies all four (unseal → lookup record → verify
signature → decrypt shards → verify AEAD tags → reconstruct → check $H(e') = \text{EntityID}$),
the adversary must break at least one. The advantage is bounded by the sum. ∎

**This is LTP's strongest security theorem.** It is a composite reduction that chains four
standard cryptographic assumptions. Under NIST Level 3 security (ML-KEM-768 + ML-DSA-65
+ BLAKE2b-256), each component provides $\geq 128$ bits of post-quantum security.

#### 3.3.7 What Cannot Be Formally Proven

| Claim | Why It Cannot Be Proven | Status |
|-------|------------------------|--------|
| "Faster than direct transfer" | Performance is empirical. Depends on topology, entity size, node placement. | Acknowledged in §6.4 (cost model) |
| "Geography-independent" | Requires commitment nodes near receivers. No protocol guarantees this. | Deployment-dependent |
| "Sub-latency transfer" | O(1) key size is proven; O(1) total latency is not. MATERIALIZE fetches O(entity) data. | Reframed as "bottleneck relocation" |
| "Secure without trust" | Requires honest append-only log and ≥ k honest shard replicas. These ARE trust assumptions. | Acknowledged in §5.1 |
| "Permanent storage" | Requires economic incentives to sustain nodes. Without incentives, rational nodes evict data. | Acknowledged in §5.4.4, §5.5 |

---

## 4. Immutability Guarantees

### 4.1 Why Immutability Is Inherent

LTP doesn't "add" immutability as a feature. Immutability is a **consequence of the design**:

1. **Entity IDs are content-addressed**: Changing one bit changes the EntityID. There is no way
   to modify an entity and keep the same identity.

2. **Commitment records are append-only**: Once published, a commitment cannot be altered or
   deleted. The log is cryptographically chained.

3. **Shards are content-addressed**: A commitment node cannot alter a shard without invalidating
   its ShardID, which would be detected at reconstruction.

4. **Lattice keys reference specific commitments**: The receiver always materializes the
   exact entity the sender committed. There is no opportunity for mutation in transit.

### 4.2 Versioning vs. Mutation

If a sender wants to "update" an entity, they commit a **new entity** with a reference to the
previous one:

```json
{
  "entity_id": "blake3:new_hash...",
  "predecessor": "blake3:old_hash...",
  "version": 2,
  ...
}
```

This creates an immutable **version chain**. Every version exists permanently. "Updating" is
actually "appending a new version." The full history is always auditable.

### 4.3 Immutability ≠ Availability

A critical distinction that protocols often conflate:

| Property | Guarantee | Condition |
|----------|----------|-----------|
| **Immutability** | If data is reconstructed, it is *exactly* what was committed | UNCONDITIONAL — content-addressing ensures any valid reconstruction is authentic. No mechanism exists to produce corrupted data with a valid EntityID. |
| **Availability** | Committed data *can* be reconstructed | CONDITIONAL — requires ≥ $k$ shard indices with ≥ 1 live replica each (see §5.4) |

**Theorem 1 (Immutability).** Let $E$ be an entity committed with EntityID $= H(E)$. Any
content $E'$ produced by the MATERIALIZE phase satisfies $E' = E$, or the integrity check
fails and the receiver obtains nothing. There is no intermediate state where the receiver
accepts incorrect data.

*Proof sketch.* MATERIALIZE verifies $H(E') = \text{EntityID}$ (step 8). AEAD tags protect
each shard against tampering. The Merkle root in the commitment record commits to the
exact set of shard hashes. Modifying any shard changes its hash, which changes the Merkle
root, which doesn't match the signed commitment. The ML-DSA signature prevents forging a
new commitment record. ∎

**Theorem 2 (Availability Boundary).** Let $A_i$ denote the event that shard index $i$ has
at least one available replica. The entity is reconstructable if and only if
$|\{i : A_i\}| \geq k$. Below this threshold, the entity is **permanently lost** — the
commitment record proves it existed, but the content cannot be recovered.

The failure mode is **graceful, not corrupted**: MATERIALIZE returns nothing rather than
partial or incorrect data. Immutability is never violated — the entity either materializes
exactly or doesn't materialize at all.

**Why this tension is fundamental.** Any distributed storage system must accept that
availability is probabilistic: disks fail, operators leave, regions go offline. LTP's
contribution is making the two guarantees *orthogonal*:

- Immutability is enforced by *cryptography* (hashes, signatures, AEAD tags) — it holds
  regardless of network state.
- Availability is enforced by *redundancy* ($k$-of-$n$ erasure coding × $r$-way
  replication) — it degrades with failures but can be restored via repair.

The `ErasureCoder` implements true any-$k$-of-$n$ reconstruction over GF(256), using a
Vandermonde encoding matrix with Gauss-Jordan decoding. This means:

- The first $k$ data shards are NOT privileged — any $k$ shards suffice
- Losing ALL data shards (indices 0 through $k-1$) is survivable if $k$ parity shards remain
- The failure boundary is sharp: at $k$ shards the entity reconstructs exactly; at $k-1$
  it is irrecoverable

See §5.4 for the full availability model, failure modes, and repair protocol.

---

## 5. Commitment Network

The protocol assumes a distributed network of commitment nodes that store encrypted shards
and serve them to authorized receivers. This section addresses how that network comes into
existence, how it resists attacks, and what availability guarantees it can offer.

### 5.1 Bootstrap: How the Network Starts

LTP defines a **permissioned genesis** with a path to progressive decentralization.

#### 5.1.1 Genesis Configuration

A deployment begins with a genesis configuration:

```json
{
  "genesis_version": 1,
  "minimum_nodes": 6,
  "minimum_regions": 3,
  "minimum_admin_domains": 2,
  "genesis_operators": [
    {"id": "operator_a", "attestation": "ml-dsa-65:vk_a...", "region": "US-East"},
    {"id": "operator_b", "attestation": "ml-dsa-65:vk_b...", "region": "EU-West"},
    {"id": "operator_c", "attestation": "ml-dsa-65:vk_c...", "region": "AP-East"}
  ],
  "admission_policy": "permissioned",
  "audit_interval_seconds": 3600
}
```

The genesis set must satisfy:
- At least $2k$ nodes (where $k$ = minimum reconstruction threshold), ensuring no single
  entity of $k$ nodes can reconstruct all shards even before considering encryption
- Nodes span $\geq 3$ geographic regions and $\geq 2$ administrative domains
- Each genesis operator provides an ML-DSA-65 verification key as identity attestation

#### 5.1.2 Why Permissioned Genesis?

A fully permissionless bootstrap (like Bitcoin's) requires a consensus mechanism from block 0
and is vulnerable to early Sybil attacks when the network is small. LTP's commitment network
is a **storage network**, not a ledger — it does not need proof-of-work or proof-of-stake for
its primary function (storing and serving encrypted shards). The trust requirement is lighter:
nodes must be **available** and **honest about storage** (they need not agree on global
transaction ordering).

Starting permissioned and progressively opening admission is the approach taken by
Certificate Transparency [7] and Hyperledger Fabric [8], both of which share LTP's
requirement for append-only integrity without full decentralized consensus.

#### 5.1.3 Progressive Decentralization

The network evolves through three stages:

| Stage | Admission | Sybil Resistance | Trust Model |
|-------|-----------|-------------------|-------------|
| **Genesis** | Curated operators only | Identity verification | Known operators |
| **Permissioned** | Application + endorsement by $m$-of-$n$ existing operators | Identity + storage proofs | Reputation + audit |
| **Open** | Self-registration + storage bond + storage proofs | Economic + cryptographic | Proof-based (minimal trust) |

Transition between stages is governed by the genesis configuration and requires a
supermajority ($\geq 2/3$) of existing operators to approve via signed votes.

### 5.2 Sybil Resistance

A Sybil attack occurs when an adversary creates many fake identities to gain disproportionate
influence. In LTP's context, a Sybil attacker controlling many nodes could:
- Dominate shard placement (receive most shards via consistent hashing)
- Coordinate to withhold shards (availability attack)
- In pre-Option-C designs, coordinate to reconstruct data (confidentiality attack — **now mitigated**)

LTP employs a dual-layer Sybil defense:

#### 5.2.1 Layer 1: Identity Verification

Every commitment node must prove its identity through one of:

| Method | Stage | Mechanism |
|--------|-------|-----------|
| Operator attestation | Genesis / Permissioned | Organizational identity verified by existing operators |
| SPIFFE/SPIRE SVID [11] | Permissioned / Open | Short-lived X.509 workload identity, automatically rotated |
| Economic bond | Open | Deposit stake to a smart contract; stake slashed on misbehavior |

Each identity method binds a node to a **verifiable identity** that is expensive to replicate
at scale. An attacker cannot cheaply create thousands of identities.

#### 5.2.2 Layer 2: Storage Proofs

Identity alone is insufficient — a node could register legitimately but not actually store
data. LTP requires ongoing **proof-of-storage** via a lightweight challenge-response protocol:

```
Auditor → Node:  Challenge(entity_id, shard_index, nonce)
Node → Auditor:  H(encrypted_shard || nonce)    [within time bound T]
```

- The auditor sends a random nonce and a specific (entity_id, shard_index) pair
- The node must return `H(ciphertext || nonce)` within a time bound $T$
- Since shards are AEAD-encrypted, the node computes over **ciphertext** — no plaintext
  access is needed and no confidentiality is compromised
- The auditor can verify the response because it knows the expected `H(ciphertext || nonce)`
  (it can compute this from the data it observed during the commit phase, or by fetching
  the shard from a different replica)

**Why this is simpler than Filecoin's Proof-of-Replication:**

Filecoin requires Proofs of Replication (PoRep) and Proofs of Spacetime (PoSt) to prevent
nodes from generating data on-the-fly or outsourcing storage. These require SNARKs, VDFs
(verifiable delay functions), and a sealing ceremony. LTP's storage proofs are lighter because:

1. **No deduplication defense needed.** Filecoin must prove *unique* physical copies exist
   (to prevent a node from storing one copy and claiming storage for many). LTP doesn't care
   about physical uniqueness — if a node can serve the correct ciphertext, that's sufficient.

2. **No proof-of-spacetime needed.** Filecoin must prove *continuous* storage over time via
   periodic SNARK proofs. LTP uses periodic random challenges — simpler but weaker. A node
   that re-fetches data just before an audit passes the challenge but doesn't actually store
   persistently. This is an accepted tradeoff: the time-bounded challenge ($T$) limits how
   far away re-fetch storage can be, and economic bonds make the penalty for audit failure
   outweigh the savings from shirking.

3. **Ciphertext is randomly verifiable.** Since encrypted shards are deterministic (same CEK +
   shard + nonce → same ciphertext), any party with a copy can verify any other party's claim.

#### 5.2.3 Audit Protocol

Audits are performed by a rotating set of auditors selected from the existing operator pool:

```
┌─────────────────────────────────────────────────────────────┐
│                    AUDIT PROTOCOL                            │
│                                                              │
│  1. Auditor selection: round-robin from operators            │
│  2. Target selection: random (entity_id, shard_index) pair   │
│     from the commitment log                                  │
│  3. Challenge: Auditor sends (entity_id, index, nonce)       │
│  4. Response: Node returns H(ciphertext || nonce) within T   │
│  5. Verification: Auditor compares against known-good hash   │
│  6. Result:                                                  │
│     ✓ Pass → node reputation +1                              │
│     ✗ Fail → strike recorded                                 │
│     ✗✗ 3 strikes → eviction + bond slash (if applicable)     │
│  7. Repair: evicted node's shards re-replicated to healthy   │
│     nodes (ciphertext only — no plaintext exposed)           │
└─────────────────────────────────────────────────────────────┘
```

The audit interval is configurable (default: every 3600 seconds per node). A node that fails
3 consecutive audits is evicted. Its shards are re-replicated from surviving replicas to
maintain the replication factor $r$.

### 5.3 Collusion Resistance

The collusion question is: **what if $k$ or more nodes conspire to pool their shards and
reconstruct an entity?**

#### 5.3.1 Pre-Option-C (Broken)

In the original design (plaintext shards), $k$ colluding nodes holding distinct shard indices
could reconstruct the full entity via erasure decoding. This was a real vulnerability.

#### 5.3.2 Post-Option-C (Mitigated)

With Option C (implemented in LTP v2), all shards are AEAD-encrypted with a random CEK before
distribution. Colluding nodes face the following:

```
k colluding nodes pool encrypted shards
  → Erasure decode ciphertext → encrypted entity (useless without CEK)
  → CEK exists ONLY inside the sealed lattice key
  → Sealed lattice key is ML-KEM-encapsulated to the receiver's ek
  → Collusion without CEK is computationally equivalent to breaking AEAD
```

**Formal argument:** Let $\mathcal{A}$ be an adversary controlling $k$ or more nodes. $\mathcal{A}$
possesses $k$ encrypted shards $\{E_i = \text{AEAD}(CEK, S_i, i)\}_{i \in K}$ where $|K| \geq k$.
To recover any plaintext shard $S_i$, $\mathcal{A}$ must break the IND-CPA security of the AEAD
scheme without knowledge of CEK. The CEK is:

- Never transmitted to any commitment node
- Only present inside the sealed lattice key (ML-KEM-768 encapsulated to receiver)
- Generated fresh per entity (no key reuse across entities)

Therefore, node collusion reduces to AEAD key recovery, which is computationally infeasible
under standard assumptions.

**What collusion CAN still achieve:**

| Attack | Can colluding nodes do it? | Mitigation |
|--------|---------------------------|------------|
| Read plaintext content | **No** — shards are AEAD-encrypted | Option C |
| Reconstruct encrypted entity | **Yes** — but useless without CEK | Option C |
| Withhold shards (availability attack) | **Yes** — denial of service | Replication + audit |
| Delete shards | **Yes** — but detected by audit | Audit + repair protocol |
| Serve corrupted shards | **No** — AEAD tag verification catches corruption | AEAD integrity |

The residual risk from collusion is **availability**, not **confidentiality**. This is addressed
in Section 5.4.

### 5.4 Data Availability

Immutability guarantees that committed data **cannot be changed**. Availability guarantees
that committed data **can be accessed**. LTP provides probabilistic availability guarantees,
not absolute ones.

#### 5.4.1 Availability Model

Given:
- $n$ = total shards per entity
- $k$ = reconstruction threshold ($k < n$)
- $r$ = replication factor (copies of each shard across independent nodes)
- $p$ = probability a single node is unavailable (crash, eviction, network partition)

A shard index $i$ is available if **at least 1** of its $r$ replicas is online:

$$P(\text{shard}_i \text{ available}) = 1 - p^r$$

The entity is available if **at least $k$** of $n$ shard indices have at least one live replica:

$$P(\text{entity available}) = \sum_{j=k}^{n} \binom{n}{j} (1 - p^r)^j \cdot (p^r)^{n-j}$$

**Worked example** ($n = 8, k = 4, r = 3, p = 0.1$):

$$P(\text{shard}_i \text{ available}) = 1 - 0.1^3 = 0.999$$

$$P(\text{entity available}) = \sum_{j=4}^{8} \binom{8}{j} (0.999)^j (0.001)^{8-j} \approx 0.999\,999\,999\,97$$

Even with 10% individual node failure rate, the combination of erasure coding ($k$-of-$n$)
and replication ($r$ copies) produces >99.9999999% availability. This is the power of
compounding two orthogonal redundancy mechanisms.

**Erasure coding guarantee.** The availability model assumes ANY $k$ shards are sufficient
for reconstruction — not just the first $k$ "data" shards. The reference implementation
achieves this via a Vandermonde encoding matrix over GF(256) with Gauss-Jordan decoding.
Shard indices are not privileged: losing all "data" shards is recoverable if $k$ "parity"
shards survive. The proof-of-concept demonstrates this explicitly (see demo: "Degraded
Materialization").

#### 5.4.2 Failure Modes and Repair

| Failure | Detection | Response |
|---------|-----------|----------|
| Single node crash | Audit challenge timeout | Re-replicate affected shards from surviving replicas |
| Region outage | Multiple audit failures in same region | Trigger cross-region re-replication |
| Node eviction (misbehavior) | 3 consecutive audit failures | Slash bond, redistribute shards |
| Correlated failure ($> n - k$ shard indices lost) | MATERIALIZE returns < k shards | Entity becomes **permanently unavailable** (committed but inaccessible) |

**Repair protocol:** When a node is evicted or detected as failed, the network executes:

```
1. Identify all (entity_id, shard_index) pairs stored on the failed node
2. For each pair, check if other replicas exist on healthy nodes
3. If replica exists: copy encrypted shard to a new node (assignment via consistent hash)
4. If no replica exists: shard index is marked DEGRADED (reduced redundancy)
5. Update replication metadata
```

Critically, repair operates on **ciphertext**. The repair process never requires the CEK or
any access to plaintext. Any authorized node can store a replica without learning content.

#### 5.4.3 The CAP Theorem and LTP

LTP's commitment network must navigate the CAP theorem:

| CAP Property | LTP's Choice |
|-------------|-------------|
| **Consistency** | Commitment log is strongly consistent (append-only, hash-chained). Shard storage is eventually consistent (replicas may lag). |
| **Availability** | Probabilistic (see §5.4.1). Not guaranteed under correlated failure of $> n - k$ shard indices. |
| **Partition Tolerance** | Supported. Partitioned regions serve locally-cached shards; commitment log reconciles post-partition. |

**Honest assessment:** LTP prioritizes **consistency** (immutability is non-negotiable) and
**partition tolerance** (geographically distributed by design). Availability is probabilistic
and degrades under correlated failures. This is the same tradeoff made by Tahoe-LAFS [3]
and Storj [4].

#### 5.4.4 Availability vs. Permanence

The commitment record is **permanent** (on the append-only log). The shards are **available
with high probability** but not guaranteed permanent:

- Shards may have a **TTL (time-to-live)** after which nodes MAY evict them
- Without economic incentives, rational nodes have no reason to store data indefinitely
- For permanent storage, senders must **renew TTL** (potentially with payment)
- The commitment record survives even if all shards are evicted — the entity is proven to
  have existed, but can no longer be materialized

This mirrors Filecoin's deal model: storage is a service, not a right. The protocol
guarantees immutability and integrity; availability requires ongoing economic commitment.

### 5.5 Network Economics (Interface, Not Implementation)

LTP intentionally does **not** specify a token, a consensus mechanism, or a fee schedule.
Instead, it defines **interfaces** that any economic layer must satisfy:

```
Interface: NodeIncentive
  - compensate(node_id, bytes_stored, seconds_stored, bytes_served) → reward
  - slash(node_id, audit_failure_count) → penalty

Interface: CommitmentPricing
  - price(entity_size, replication_factor, ttl_seconds) → cost
  - renew(entity_id, additional_ttl) → cost

Interface: AdmissionControl
  - apply(node_identity, storage_proof, bond) → accepted | rejected
  - evict(node_id, reason, audit_evidence) → confirmation
```

**Why not specify economics?** The optimal incentive mechanism depends on deployment context:

| Deployment | Economic Model | Example |
|-----------|---------------|---------|
| Enterprise (private) | Organizational obligation | Internal SLA — nodes run by IT departments |
| Consortium | Mutual obligation + SLA | CT log operators [7] — run by CAs for collective benefit |
| Public (open) | Token/payment + staking | Filecoin [5], Storj [4] — economic incentives |

Specifying a token would limit LTP to public deployments. Specifying organizational obligation
would limit it to enterprises. The interface layer allows any of these.

---

## 6. Breaking the Constraints

### 6.1 Latency

**Traditional**: Latency = f(distance, hops, payload_size)  
**LTP**: Latency = f(key_transmission) + f(nearest_shard_fetch)

The sealed lattice key is ~1,300 bytes (increased from ~240 bytes pre-quantum due to
ML-KEM-768 ciphertext overhead — the honest cost of quantum resistance). Its transmission
is near-instantaneous on any network. Shard fetching is parallelized from the nearest nodes.

**What this means precisely:**
- The sender→receiver latency is reduced to O(1) (the key is constant-size)
- The materialization latency depends on the receiver's proximity to commitment nodes
- If commitment nodes exist near the receiver, effective latency approaches local RTT
- If no nearby nodes exist, shard fetching still incurs geographic latency

**What this does NOT mean:** Total time is not "near-instantaneous" for large entities.
The receiver still downloads O(entity) bytes of encrypted shards. The advantage is that
this download is from *nearby nodes* in parallel, not from a distant sender over a single
path.

### 6.2 Geographic Distance

**Traditional**: New York → Tokyo = ~200ms RTT minimum (speed of light through fiber).  
For a 1 GB file at 100 Mbps effective throughput: ~80 seconds, bottlenecked by the single path.

**LTP**: The sender in New York transmits a ~1,300-byte sealed key to the receiver in Tokyo
(one round trip, ~200ms). The receiver then fetches k encrypted shards in parallel from
Tokyo-local commitment nodes (~5-10ms RTT each). Materialization time is dominated by
*local bandwidth*, not transoceanic latency.

The geographic cost is paid **once** when shards are distributed to the commitment network
during the commit phase (this happens asynchronously, before any receiver is involved).
Subsequent materializations by any receiver anywhere draw from *nearby nodes*.

**Honest tradeoff:** The commit phase requires distributing O(entity × replication) bytes
across the global network. For a single sender → single receiver transfer, total system
bandwidth is higher than direct transfer. The advantage appears in:
- **Fan-out:** one commit, many receivers — amortized cost per receiver approaches zero
- **Latency:** receiver-local fetches vs. sender-distance fetches
- **Sender-independence:** sender can go offline after commit

### 6.3 Computing Power

**Traditional**: Sender must serialize, compress, encrypt, and transmit. Receiver must receive,
decrypt, decompress, and deserialize. Both need sufficient compute.  
**LTP**: The heavy work (erasure encoding, shard distribution) is done once at commit time and
can be offloaded to the commitment network. Materialization (erasure decoding from k shards) is
computationally lightweight and highly parallelizable.

### 6.4 Formal Cost Model

Let:
- $D$ = entity size in bytes
- $n$ = total shards, $k$ = reconstruction threshold
- $r$ = replication factor per shard
- $N$ = number of receivers
- $L_{SR}$ = latency between sender and receiver
- $L_{RN}$ = latency between receiver and nearest commitment node

**Bandwidth costs:**

| Metric | Direct Transfer | LTP |
|--------|----------------|-----|
| Sender upload (per transfer) | $D$ | — (already committed) |
| Sender upload (commit, once) | — | $D \cdot r$ |
| Sender→receiver direct | $D$ | $O(1)$ (~1,300 bytes) |
| Receiver download | $D$ | $D$ (k shards × $D/k$) |
| **Total system, 1 receiver** | $D$ | $D \cdot r + D \approx D(r+1)$ |
| **Total system, N receivers** | $D \cdot N$ | $D \cdot r + D \cdot N$ |
| **Amortized per receiver (N large)** | $D$ | $\approx D$ |

**Key formula — total system bandwidth:**

$$B_{LTP}(N) = D \cdot r + D \cdot N$$
$$B_{direct}(N) = D \cdot N$$

For $N = 1$: $B_{LTP} = D(r+1) > D = B_{direct}$. **LTP is strictly worse for single-transfer bandwidth.**

For $N > r$: $B_{LTP} \approx D \cdot N \approx B_{direct}$. **LTP amortizes to parity.**

For large $N$: The commit cost $D \cdot r$ becomes negligible. Each additional receiver costs only
$D$ (local shard fetches) + ~1,300 bytes (sealed key). Sender bandwidth is constant after commit.

**Latency costs:**

$$T_{direct} = L_{SR} + \frac{D}{\text{bandwidth}_{SR}}$$

$$T_{LTP} = \underbrace{\frac{1300}{\text{bandwidth}_{SR}}}_{\text{key (negligible)}} + \underbrace{\frac{D/k}{\text{bandwidth}_{RN}}}_{\text{k parallel shard fetches}}$$

When $\text{bandwidth}_{RN} \gg \text{bandwidth}_{SR}$ (receiver is near commitment nodes but far from
sender), $T_{LTP} \ll T_{direct}$. This is the latency advantage.

When $\text{bandwidth}_{RN} \approx \text{bandwidth}_{SR}$ (everything is equidistant), $T_{LTP} \approx T_{direct}$
but with the sender free to go offline.

**Where LTP wins honestly:**
1. Fan-out: $N$ receivers for near-constant sender cost
2. Latency: receiver-local fetches vs. sender-distance fetches
3. Sender-independence: sender contributes zero bandwidth after commit
4. Availability: shards survive sender going offline

**Where LTP loses honestly:**
1. Single-transfer bandwidth: $r+1$ times worse than direct
2. Storage: the commitment network stores $D \cdot r$ bytes persistently
3. Complexity: three-phase protocol vs. one-phase direct send

---

## 7. Comparison with Existing Approaches

| Property | TCP/IP | IPFS | BitTorrent | Tahoe-LAFS | Storj | **LTP** |
|----------|--------|------|-----------|------------|-------|---------|
| Payload travels sender→receiver | Yes | Partial | Partial | No | No | **No** |
| Content-addressed | No | Yes | Partial | Yes | Yes | **Yes** |
| Immutable | No | Yes | No | Yes | Yes | **Yes** |
| Client-side encryption | TLS layer | No | No | **Yes** | **Yes** | **Yes** |
| Shards encrypted at rest | N/A | No | No | **Yes** | **Yes** | **Yes** |
| Erasure-coded redundancy | No | No | No | **Yes** | **Yes** | **Yes** |
| Sender→receiver path O(1) | No | No | No | No | No | **Yes** |
| Capability-based access control | No | No | No | **Yes** | **Yes** | **Yes** |
| Capability bound to receiver identity | No | No | No | No | No | **Yes (ML-KEM)** |
| Forward secrecy (PQ) | TLS layer | No | No | No | No | **Yes (ML-KEM)** |
| PQ signatures on commitments | No | No | No | No | No | **Yes (ML-DSA)** |
| ZK privacy mode | No | No | No | No | No | **Yes** |
| Survives sender going offline | No | If pinned | If seeded | **Yes** | **Yes** | **Yes** |
| Receiver proximity optimization | No | Partial | Partial | No | Partial | **Yes** |
| Deterministic shard placement | No | DHT | DHT peers | Server-assigned | Server-assigned | **Consistent hash** |
| Append-only audit log | No | No | No | No | No | **Yes** |

**Reading guide:** LTP's unique cells (only LTP has "Yes") are: O(1) sender→receiver path,
receiver-bound capabilities, per-message PQ forward secrecy, PQ-signed append-only audit log,
and ZK privacy mode. The encrypted storage, erasure coding, and capability-based access that
LTP shares with Tahoe-LAFS and Storj are acknowledged as prior art — see Section 8.

---

## 8. Related Work and Prior Art

LTP is not built in a vacuum. Its design draws from, recombines, and extends ideas pioneered by
decades of work in distributed systems, cryptography, and peer-to-peer networking. This section
honestly acknowledges the lineage and articulates what — if anything — LTP contributes beyond
its predecessors.

### 8.1 Content-Addressed Storage

**IPFS (InterPlanetary File System, 2015)** [1] introduced content-addressed, Merkle-DAG-based
storage to mainstream distributed systems. In IPFS, files are split into blocks, each identified
by a cryptographic hash (CID), and retrieved by requesting the CID from the network. Peers who
have fetched a block can re-serve it, creating BitTorrent-like swarming.

**Git (2005)** [2] pioneered the idea that a repository's entire history could be addressed by
content hashes (SHA-1, now SHA-256). Every commit, tree, and blob is content-addressed, making
the history immutable and independently verifiable.

**What LTP borrows:** Content-addressing as the identity function (`EntityID = H(content || ...)`).
This is not novel — it is a direct application of the same principle.

**Where LTP diverges:** In IPFS, any peer with the CID can fetch the content; there is no built-in
access control. In LTP, knowing the `entity_id` is insufficient — the receiver also needs the
Content Encryption Key (CEK), which is sealed inside the lattice key. IPFS retrieval is
*permissionless*; LTP materialization is *capability-gated*. Additionally, LTP encrypts all shards
at rest (AEAD with CEK), whereas IPFS blocks are stored and served in plaintext by default.

### 8.2 Erasure-Coded Distributed Storage

**Tahoe-LAFS (Least-Authority File Store, 2007)** [3] was among the first systems to combine
erasure coding with capability-based access control for untrusted storage. Files are encrypted
client-side, erasure-coded into shares, and distributed to storage servers. Capabilities (read-caps,
write-caps) are unforgeable tokens that grant specific access rights. Tahoe-LAFS coined the
principle: *"the server doesn't learn anything about the data."*

**Storj (2018)** [4] applies Reed-Solomon erasure coding over a decentralized network of storage
nodes. Files are encrypted client-side, split into 80 pieces (of which any 29 can reconstruct),
and distributed to independent operators. Access grants (serialized macaroons) authorize retrieval.

**Filecoin (2020)** [5] extends IPFS with cryptoeconomic guarantees: storage providers submit
Proofs of Replication and Proofs of Spacetime to demonstrate that data is physically stored.
This addresses the data availability problem that LTP's Section 10 (Open Questions) leaves open.

**What LTP borrows:** Erasure coding for redundancy and threshold reconstruction (k-of-n); client-side
encryption before distribution; the property that storage nodes cannot read content.

**Where LTP diverges:** Tahoe-LAFS, Storj, and Filecoin are *storage systems* — they address "how
do I store data durably on untrusted nodes?" LTP frames the same infrastructure as a *transfer
protocol* — the question is "how does entity X get from sender A to receiver B," with the storage
layer as an intermediate step rather than the end goal. The distinction is one of framing and
protocol-level abstraction: LTP's three-phase model (commit → lattice → materialize) treats
the distributed storage as a side-effect of the commit phase, not as the primary interface.

Whether this framing is a meaningful contribution or merely a relabeling is a fair question.
We argue the value lies in the protocol-level UX: the sender thinks in terms of "commit and
lattice," not "upload to storage provider and share access grant." The operational semantics
differ even if the underlying mechanisms are similar.

### 8.3 Append-Only Commitment Logs

**Bitcoin (2008)** [6] introduced the hash-chained, proof-of-work append-only ledger. Each block
references the hash of the previous block, making history tamper-evident.

**Certificate Transparency (2013)** [7] applies Merkle-tree append-only logs to TLS certificate
issuance. CAs must publish certificates to public logs, and anyone can verify that a certificate
was (or was not) logged. CT logs are simpler than blockchain — they require only a trusted log
operator (or multiple operators for cross-verification) rather than decentralized consensus.

**Hyperledger Fabric (2018)** [8] demonstrates that append-only commitment logs need not be
permissionless blockchains — permissioned channels with endorsement policies can achieve
immutability with lower latency and without proof-of-work.

**What LTP borrows:** The commitment log is a direct application of these ideas. The whitepaper
deliberately does not specify a consensus mechanism (Section 10, Open Question 3) — it could be
a blockchain, a CT-style Merkle log, or a permissioned ledger. The immutability guarantee
(Section 4) relies only on the append-only property and hash chaining, not on a specific
consensus protocol.

**Where LTP diverges:** LTP's commitment log is minimal by design: it stores only a Merkle root
of encrypted shard hashes, the entity_id, encoding params, and an ML-DSA signature. No shard
IDs, no content, no CEK. This is a tighter interface than most blockchain-based systems, which
tend to store more metadata. The log's purpose is *attestation* ("this entity was committed by
this sender at this time"), not general-purpose state management.

### 8.4 Capability-Based Security

**Dennis & Van Horn (1966)** [9] introduced the capability model: an unforgeable token that
simultaneously designates a resource and authorizes access to it. The holder of a capability
can access the resource; without it, the resource is unreachable. Capabilities are the
*minimum viable authorization* — no identity checks, no ACLs, just possession of proof.

**Macaroons (2014)** [10] extended capabilities with *caveats* — conditions that can be added
by any party in the delegation chain (e.g., "valid until 2026-03-24," "only from IP range X").
Storj uses serialized macaroons as its access grant format.

**SPIFFE/SPIRE (2017+)** [11] provides workload identity in distributed systems via short-lived
X.509 certificates (SVIDs), enabling zero-trust service-to-service authentication.

**What LTP borrows:** The lattice key is a capability. It designates a resource (the
committed entity) and authorizes a specific receiver to materialize it. The `access_policy`
field (one-time, time-bounded, delegatable) is directly inspired by macaroon caveats.

**Where LTP diverges:** The lattice key combines capability semantics with envelope
encryption (ML-KEM). A Storj access grant can be used by anyone who possesses it; an LTP
lattice key is sealed to a specific receiver's encapsulation key and is useless to anyone
else. This binds the capability to a cryptographic identity, not just to possession.

### 8.5 Peer-to-Peer Content Distribution

**BitTorrent (2001)** [12] demonstrated that large-file distribution could be decentralized:
the original seeder uploads once, and peers exchange pieces among themselves. The more popular
a file becomes, the faster it distributes (unlike client-server, where popularity causes
congestion). BitTorrent's piece model (splitting content into fixed-size chunks distributed
across peers) is an ancestor of LTP's shard model.

**NDN (Named Data Networking, 2009+)** [13] proposes replacing IP's host-centric architecture
with data-centric networking: consumers request data by name, and any node that has a cached
copy can serve it. The network layer itself becomes content-addressed. NDN's "fetch from
wherever is closest" philosophy directly parallels LTP's receiver-side materialization from
nearest commitment nodes.

**What LTP borrows:** Parallel multi-source fetching (from BitTorrent/NDN), the principle that
the first upload is the expensive operation and subsequent retrievals amortize the cost, and
the idea that content should flow from where it is cached rather than from a fixed origin.

**Where LTP diverges:** BitTorrent has no built-in encryption or access control — torrents are
public by default. NDN's data-centric model operates at the network layer, while LTP is an
application-layer protocol. LTP's commitment phase is a one-time sender operation (not a
continuous seeding obligation), and the commitment network serves encrypted shards without
needing to understand or index the content.

### 8.6 Hybrid and Convergent Systems

Several systems have independently converged on similar combinations:

**Tahoe-LAFS + Capability Model** arguably comes closest to LTP's design: encrypted erasure-coded
storage with capability-based access. LTP's main departure is the protocol framing (transfer vs.
storage), the ML-KEM sealed envelope (binding capabilities to a specific receiver), and the
explicit three-phase model with an append-only commitment log.

**Keybase (2014-2020)** [14] combined KBFS (an encrypted, content-addressed filesystem) with
public-key identity and Merkle-tree-based audit logs. Users could share files by name, with
client-side encryption and server-side ignorance — similar to LTP's "nodes store ciphertext."

**Secure Scuttlebutt (SSB, 2014+)** [15] uses append-only logs per identity, with content-
addressed messages and capability-based private groups. SSB's offline-first design (gossip
replication, no central server) parallels LTP's sender-independence property.

### 8.7 What LTP Contributes

Given the depth of prior art, the honest answer is: **LTP's individual components are not novel.
Its contribution is the protocol-level synthesis.**

Specifically:

1. **The three-phase model (commit → lattice → materialize) as a transfer primitive.** Prior
   systems treat content-addressed storage + capabilities as *storage with sharing*. LTP treats
   the combination as *a data transfer protocol* — an alternative to sending payloads. This is
   primarily a conceptual contribution. Whether it proves practically valuable depends on
   whether the abstraction enables workflows that existing tools make awkward.

2. **The sealed lattice key as a constant-size, receiver-bound, post-quantum transfer
   token.** Unlike Storj access grants (bearer tokens, anyone who holds them can use them),
   the lattice key is cryptographically bound to a specific receiver via ML-KEM-768.
   Unlike Tahoe-LAFS read-caps (static, no expiry built-in), the lattice key includes
   inline access policy (one-time, time-bounded, delegatable) and uses per-seal forward
   secrecy. The combination of capability + receiver binding + per-message forward secrecy +
   inline policy in a constant-size token is, to our knowledge, not present in prior systems.

3. **Deterministic receiver-side location derivation.** In IPFS and Storj, the provider/sharer
   must communicate block CIDs or shard locations to the receiver explicitly. In LTP, the
   receiver computes shard locations from the entity_id via consistent hashing — no lookup
   service, no external metadata. This eliminates one round-trip and one point of failure.

4. **Post-quantum security as a default, not an upgrade path.** ML-KEM-768 for key encapsulation
   and ML-DSA-65 for signatures are the *default* primitives, not optional add-ons. Most
   existing distributed storage systems use X25519/Ed25519 and mention post-quantum as future
   work.

We make no claim that these contributions are individually groundbreaking. The question for the
reader is whether the synthesis, and the mental model it enables ("don't move the data — transfer
the proof"), justifies a dedicated protocol specification. We believe it does, but acknowledge
that reasonable reviewers may disagree.

### References

[1] J. Benet, "IPFS — Content Addressed, Versioned, P2P File System," arXiv:1407.3561, 2014.

[2] L. Torvalds, "Git: A distributed version control system," 2005. https://git-scm.com/

[3] Z. Wilcox-O'Hearn, "Tahoe — The Least-Authority Filesystem," ACM CCS StorageSS Workshop, 2008.

[4] Storj Labs, "Storj: A Decentralized Cloud Storage Network Framework," Storj Whitepaper v3, 2018.

[5] Protocol Labs, "Filecoin: A Decentralized Storage Network," Filecoin Whitepaper, 2017 (mainnet 2020).

[6] S. Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System," 2008.

[7] B. Laurie, A. Langley, E. Kasper, "Certificate Transparency," RFC 6962, 2013.

[8] E. Androulaki et al., "Hyperledger Fabric: A Distributed Operating System for Permissioned Blockchains," EuroSys, 2018.

[9] J. B. Dennis and E. C. Van Horn, "Programming Semantics for Multiprogrammed Computations," Communications of the ACM, 9(3), 1966.

[10] A. Birgisson, J. G. Politz, U. Erlingsson, A. Taly, M. Vrable, M. Lentczner, "Macaroons: Cookies with Contextual Caveats for Decentralized Authorization in the Cloud," NDSS, 2014.

[11] CNCF, "SPIFFE: Secure Production Identity Framework for Everyone," https://spiffe.io/, 2017.

[12] B. Cohen, "Incentives Build Robustness in BitTorrent," Workshop on Economics of P2P Systems, 2003.

[13] L. Zhang et al., "Named Data Networking," ACM SIGCOMM CCR, 2014. (NDN project started 2009.)

[14] Keybase, Inc., "Keybase filesystem (KBFS)," https://book.keybase.io/docs/files, 2014-2020.

[15] D. Tarr et al., "Secure Scuttlebutt: An Identity-Centric Protocol for Subjective and Decentralized Applications," IFIP, 2019.

---

## 9. Use Cases

### 9.1 Large File Fan-Out
A 50 GB dataset is committed once. Any number of receivers can materialize it by each receiving
a ~1,300-byte sealed lattice key (ML-KEM-768). Each receiver's materialization time is
dominated by local shard fetching from nearby nodes — not by the sender's bandwidth or
availability. For N receivers, direct transfer costs O(50GB × N). LTP costs O(50GB ×
replication) for the commit plus O(~1,300B × N) for the keys — amortized cost per receiver
approaches zero as N grows.

### 9.2 Immutable Audit Trail
Every data transfer is permanently recorded. A compliance system can verify: "Entity X was
committed by Sender A at time T and lattice-linked with Receiver B." No party can deny or alter this.

### 9.3 Secure Messaging
A message is committed and lattice-linked. The lattice key is the message notification. The
content never traverses the public internet as a readable payload. Even if intercepted, the
lattice key alone is useless.

### 9.4 State Synchronization
Two distributed systems synchronize state by exchanging lattice keys. Each system materializes
the other's state from the commitment network. This is faster than traditional replication because
shards are fetched locally, and only the delta (new entity) needs materialization.

### 9.5 Cross-Planetary Data Transfer
On a Mars colony with 4-24 minute light delay to Earth: commitment nodes on Mars cache shards.
A sender on Earth commits an entity. The ~1,300-byte sealed lattice key crosses the void
once (4-24 minutes). The receiver on Mars materializes from Mars-local commitment nodes (which
replicate shards during off-peak periods). Materialization time is bounded by Mars-local network
speed, not Earth-Mars light delay. Note: initial shard replication to Mars nodes still incurs
the light-delay cost — the advantage is that this is amortized across all Mars-side receivers
and can happen asynchronously before any specific transfer.

---

## 10. Open Questions

1. ~~**Commitment network economics**: How are commitment nodes incentivized to store and serve shards?~~
   **Addressed in §5.5.** LTP defines economic interfaces (compensate, slash, pricing) without
   mandating a specific mechanism. Deployment-dependent: organizational SLA, mutual obligation,
   or token/staking (see §5.5 table).

2. **Shard eviction**: When can shards be garbage collected? (Never? After TTL? After all authorized
   receivers materialize?) **Partially addressed in §5.4.4** — TTL-based eviction with renewal.
   Open: optimal TTL default, interaction between TTL expiry and in-flight lattice keys.

3. ~~**Commitment log consensus**: What consensus mechanism secures the append-only log?~~
   **Addressed in §5.1.2.** LTP does not require full BFT consensus. The commitment network is
   a storage network; the log requires only append-only integrity and hash chaining. A Certificate
   Transparency–style Merkle log with trusted operators is sufficient.

4. **Bandwidth for initial shard distribution**: The commit phase still requires distributing n
   shards. Can this be amortized or pipelined?

5. **Real-time streaming**: Can LTP support continuous entity streams (video, telemetry), or is it
   inherently batch-oriented?

6. **Audit protocol formalization**: The storage proof challenge-response (§5.2.2) is lightweight
   but weaker than Filecoin's PoSt. A node that re-fetches data just before an audit passes
   dishonestly. Can time-bounded challenges be tightened without requiring SNARKs?

7. **Cross-deployment federation**: How do independently bootstrapped LTP networks discover and
   trust each other's commitment nodes?

---

## 11. Conclusion

LTP inverts the data transfer paradigm. Rather than asking "how do I send this data to you," it
asks "how do I prove this data exists, and give you the right to reconstruct it near you."

The result is a protocol where:
- **The sender→receiver path is O(1)** — a constant-size sealed key (~1,300B), regardless of entity size
- **Total system bandwidth is higher than direct transfer** — but the bottleneck shifts from
  the sender-receiver link to receiver-local fetches, with amortized fan-out
- **Transfer is immutable** by mathematical construction, not policy
- **Security is cryptographic** not perimeter-based
- **Geography is optimized** because materialization pulls from nearby nodes
- **The sender can go offline** after commitment without affecting the transfer

Data doesn't move. Proof moves. Truth materializes.
Bandwidth doesn't disappear. It redistributes to where it's cheapest.

---

*LTP v0.1.0-draft — Lattice Transfer Protocol*
