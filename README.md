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

```
┌─────────────────────────────────────────────────────────────────────────┐
│                       LATTICE TRANSFER PROTOCOL                         │
│                                                                         │
│  ┌──────────┐  ~1,300 bytes    ┌──────────┐                            │
│  │  SENDER  │ ════════════════ │ RECEIVER │                            │
│  │          │  ML-KEM sealed   │          │                            │
│  └────┬─────┘  (opaque)        └────┬─────┘                            │
│       │                             │                                   │
│       │ COMMIT                      │ MATERIALIZE                       │
│       │ (encrypted shards)          │ (unseal → derive → fetch → decrypt)│
│       ▼                             ▼                                   │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    COMMITMENT LAYER                              │   │
│  │                                                                  │   │
│  │  ┌───────────────────────────────────────────────────────────┐  │   │
│  │  │              COMMITMENT LOG (Append-Only)                  │  │   │
│  │  │  Record 1 ← Record 2 ← Record 3 ← ... ← Record N        │  │   │
│  │  │  (Merkle root of ciphertext hashes only — no shard IDs)    │  │   │
│  │  └───────────────────────────────────────────────────────────┘  │   │
│  │                                                                  │   │
│  │  ┌───────────────────────────────────────────────────────────┐  │   │
│  │  │           COMMITMENT NODES (Encrypted Shard Storage)       │  │   │
│  │  │                                                            │  │   │
│  │  │  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐  ┌─────┐          │  │   │
│  │  │  │ N1  │  │ N2  │  │ N3  │  │ N4  │  │ N5  │  ...     │  │   │
│  │  │  │ 🔒  │  │ 🔒  │  │ 🔒  │  │ 🔒  │  │ 🔒  │          │  │   │
│  │  │  │ 🔒  │  │ 🔒  │  │ 🔒  │  │ 🔒  │  │ 🔒  │          │  │   │
│  │  │  └─────┘  └─────┘  └─────┘  └─────┘  └─────┘          │  │   │
│  │  │  AEAD-encrypted ciphertext — nodes cannot read content   │  │   │
│  │  └───────────────────────────────────────────────────────────┘  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Transfer Flow

```
 Sender                    Commitment Layer              Receiver
   │                             │                          │
   │  1. Compute EntityID        │                          │
   │  2. Erasure encode → shards │                          │
   │  3. Generate CEK (random)   │                          │
   │  4. AEAD encrypt each shard │                          │
   │  5. Distribute encrypted ──▶│                          │
   │     shards to nodes         │  (ciphertext stored on   │
   │                             │   nodes by (eid, index)) │
   │  6. Write commitment ──────▶│                          │
   │     record to log           │  (Merkle root only,      │
   │     (NO shard_ids)          │   no shard_ids)          │
   │                             │                          │
   │  7. Generate lattice key    │                          │
   │     (entity_id + CEK        │                          │
   │     + ref + policy)         │                          │
   │  8. Seal key to receiver ──────────────────────────▶  │
   │     (~1,300 bytes, ML-KEM)  │                          │
   │                             │                          │
   │  ✓ Sender done.             │          9. Unseal key   │
   │    Can go offline.          │             (private key) │
   │                             │         10. Extract CEK   │
   │                             │◀──────  11. Fetch record  │
   │                             │         12. Verify record │
   │                             │                          │
   │                             │         13. Derive shard  │
   │                             │             locations     │
   │                             │◀──────  14. Fetch k       │
   │                             │──────▶      encrypted     │
   │                             │             shards        │
   │                             │                          │
   │                             │         15. AEAD decrypt  │
   │                             │             with CEK      │
   │                             │         16. Erasure decode│
   │                             │         17. Verify entity │
   │                             │                          │
   │                             │         ✓ ENTITY          │
   │                             │           MATERIALIZED    │
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

This protocol specification is released for open exploration and research.
