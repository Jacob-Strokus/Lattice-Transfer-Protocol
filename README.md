# Lattice Transfer Protocol (LTP)

### A Novel Data Transfer Protocol

> "Don't move the data. Transfer the proof. Reconstruct the truth."

---

## The Problem With Data Transfer Today

Every existing protocol — TCP/IP, HTTP, FTP, QUIC, even modern streaming protocols — operates
on the same foundational assumption:

**Data is a payload that must travel from Point A to Point B.**

This assumption chains us to three unsolvable constraints:
1. **Latency** — bound by the speed of light and routing hops
2. **Geography** — further = slower, always
3. **Compute** — larger payloads demand more processing at both ends

LTP rejects this assumption entirely.

---

## The Core Thesis

**Data transfer is not about moving bits. It is about transferring the *ability to reconstruct* a
deterministic output at a destination, verified by an immutable commitment.**

An LTP transfer consists of three atomic operations:

| Phase | Name | What Happens |
|-------|------|-------------|
| 1 | **Commit** | The sender creates an immutable, content-addressed commitment of the entity |
| 2 | **Lattice** | A minimal proof (the "lattice key") is transmitted to the receiver |
| 3 | **Materialize** | The receiver deterministically reconstructs the entity from distributed sources using the proof |

The entity is never serialized and shipped as a monolithic payload. It is **committed, proved, and reconstructed**.

---

## How It Works

### System Overview

```mermaid
flowchart TB
    S["SENDER"] -. "~1,300 byte sealed lattice key\n(ML-KEM-768 · opaque)" .-> R["RECEIVER"]

    S -->|"COMMIT\n(encrypted shards)"| CL
    R -->|"MATERIALIZE\n(unseal → fetch → decrypt)"| CL

    subgraph CL["COMMITMENT LAYER"]
        direction TB
        LOG["Commitment Log · Append-Only\nMerkle root of ciphertext hashes\nML-DSA-65 signed records"]

        subgraph NODES["Commitment Nodes · Encrypted Shard Storage"]
            direction LR
            N1["N1"] ~~~ N2["N2"] ~~~ N3["N3"] ~~~ N4["N4"] ~~~ N5["N5"]
        end

        LOG --- NODES
    end
```

> **Key insight:** The sender-to-receiver path carries only ~1,300 bytes regardless of entity size.
> All O(entity) work happens between sender↔network (commit) and network↔receiver (materialize),
> where nodes are geographically close to the receiver.

### Transfer Flow

```mermaid
sequenceDiagram
    participant S as Sender
    participant CL as Commitment Layer
    participant R as Receiver

    rect rgba(0, 128, 0, 0.08)
        Note right of S: PHASE 1 · COMMIT
        S->>S: EntityID = H(content ‖ shape ‖ ts ‖ pk)
        S->>S: Erasure encode → n shards (Reed-Solomon)
        S->>S: CEK ← CSPRNG(256 bits)
        S->>S: AEAD encrypt each shard with CEK
        S->>CL: Distribute encrypted shards to nodes
        S->>CL: Sign & write commitment record
    end

    rect rgba(255, 165, 0, 0.08)
        Note over S,R: PHASE 2 · LATTICE
        S->>S: Build lattice key (entity_id + CEK + ref + policy)
        S-->>R: Seal to receiver (~1,300 bytes via ML-KEM-768)
    end

    Note right of S: Sender done · can go offline

    rect rgba(0, 100, 255, 0.08)
        Note left of R: PHASE 3 · MATERIALIZE
        R->>R: Unseal lattice key (receiver private key)
        R->>R: Extract CEK, entity_id, commitment_ref
        R->>CL: Fetch & verify commitment record (ML-DSA-65)
        R->>R: Derive shard locations via ConsistentHash
        R->>CL: Fetch k encrypted shards (parallel, nearest-first)
        CL-->>R: Return encrypted shards
        R->>R: AEAD decrypt → plaintext shards
        R->>R: Erasure decode → reconstruct entity
        R->>R: Verify H(entity) == entity_id
    end

    Note right of R: Entity Materialized
```

### Security Stack

```mermaid
block-beta
    columns 1
    L6["Layer 6 · ACCESS POLICY\nOne-time materialization · time-bounded · delegatable · revocable"]
    L5["Layer 5 · SEALED ENVELOPE (ML-KEM-768)\nFresh encapsulation per seal · forward secrecy · zero metadata leakage"]
    L4["Layer 4 · SHARD ENCRYPTION (AEAD)\nRandom 256-bit CEK · per-shard nonce · nodes store ciphertext only"]
    L3["Layer 3 · ZERO-KNOWLEDGE (Optional)\nGroth16 / BLS12-381 · EntityID hiding · not post-quantum"]
    L2["Layer 2 · CRYPTOGRAPHIC INTEGRITY\nBLAKE3 content addressing · Merkle roots · ML-DSA-65 signatures"]
    L1["Layer 1 · INFORMATION-THEORETIC SECURITY\nReed-Solomon erasure coding · k-of-n threshold · fewer than k shards reveal nothing"]

    style L6 fill:#6b5f3a,color:#fff
    style L5 fill:#345f7a,color:#fff
    style L4 fill:#3d4e6b,color:#fff
    style L3 fill:#4a5e5a,color:#fff
    style L2 fill:#375c45,color:#fff
    style L1 fill:#374550,color:#fff
```

### Layer Breakdown

```mermaid
graph TD
    subgraph L6["Layer 6 · Access Policy"]
        L6P["Primitive: access_policy field in lattice key"]
        L6G["One-time materialization · Time-bounded\nDelegatable · Revocable"]
        L6P ~~~ L6G
    end

    subgraph L5["Layer 5 · Sealed Envelope"]
        L5P["Primitive: ML-KEM-768  FIPS 203"]
        L5G["Post-quantum key encapsulation\nFresh per-seal · Forward secrecy · Receiver-bound · Zero metadata leakage"]
        L5P ~~~ L5G
    end

    subgraph L4["Layer 4 · Shard Encryption"]
        L4P["Primitive: AEAD  AES-256-GCM or ChaCha20-Poly1305\n256-bit CEK generated fresh per entity"]
        L4G["Per-shard nonces derived from H(CEK || entity_id || index)\nCommitment nodes store ciphertext only"]
        L4P ~~~ L4G
    end

    subgraph L3["Layer 3 · Zero-Knowledge  Optional"]
        L3P["Primitive: Groth16 over BLS12-381"]
        L3G["EntityID hiding via Poseidon commitment\nblind_id = Poseidon(entity_id || r)\nNot post-quantum -- see Layer 5 for PQ guarantee"]
        L3P ~~~ L3G
    end

    subgraph L2["Layer 2 · Cryptographic Integrity"]
        L2P["Primitives: BLAKE3-256 · ML-DSA-65  FIPS 204"]
        L2G["Content addressing: EntityID = H(content || shape || timestamp || sender_pk)\nMerkle root of ciphertext hashes in commitment log\nML-DSA-65 signed commitment records"]
        L2P ~~~ L2G
    end

    subgraph L1["Layer 1 · Information-Theoretic Security"]
        L1P["Primitive: Reed-Solomon n-of-k erasure coding over GF(256)"]
        L1G["Fewer than k shards reveal zero information about entity content\nShannon perfect secrecy -- holds against unbounded adversaries\nAny k-of-n shard subset reconstructs -- no privileged shards"]
        L1P ~~~ L1G
    end

    L6 --> L5 --> L4 --> L3 --> L2 --> L1

    classDef l6 fill:#6b5f3a,color:#fff,stroke:#fff
    classDef l5 fill:#345f7a,color:#fff,stroke:#fff
    classDef l4 fill:#3d4e6b,color:#fff,stroke:#fff
    classDef l3 fill:#4a5e5a,color:#fff,stroke:#fff
    classDef l2 fill:#375c45,color:#fff,stroke:#fff
    classDef l1 fill:#374550,color:#fff,stroke:#fff

    class L6P,L6G l6
    class L5P,L5G l5
    class L4P,L4G l4
    class L3P,L3G l3
    class L2P,L2G l2
    class L1P,L1G l1

    style L6 fill:#6b5f3a28,stroke:#6b5f3a
    style L5 fill:#345f7a28,stroke:#345f7a
    style L4 fill:#3d4e6b28,stroke:#3d4e6b
    style L3 fill:#4a5e5a28,stroke:#4a5e5a
    style L2 fill:#375c4528,stroke:#375c45
    style L1 fill:#37455028,stroke:#374550
```

---

## Read the Full Specification

- [Protocol Whitepaper](docs/WHITEPAPER.md) — Full conceptual design
- [Architecture](docs/ARCHITECTURE.md) — System architecture and components
- [Proof-of-Concept](src/) — Reference implementation

---

## Quick Start

```
See docs/WHITEPAPER.md for the full protocol design.
See docs/ARCHITECTURE.md for system diagrams and component breakdown.
```

## License

This project uses a split license to distinguish the specification from the implementation.

| Artifact | License | What it means |
|----------|---------|---------------|
| Reference implementation (`src/`) | [Elastic License 2.0](LICENSE) | Use freely; cannot be offered as a managed/hosted service |
| Specification & documentation (`docs/`) | [CC BY-ND 4.0](LICENSE-SPEC) | Share freely; no modifications or derivative specs without permission |

Copyright (c) 2026 Jas Strokus
