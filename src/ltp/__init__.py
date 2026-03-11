"""
Lattice Transfer Protocol (LTP) — Proof of Concept v3 (Post-Quantum Security)

Implements the three core phases of LTP with post-quantum cryptographic primitives:

  1. COMMIT      — Entity → Erasure Encode → Encrypt Shards with CEK → Distribute Ciphertext
  2. LATTICE     — Generate minimal sealed key (~160B inner, ~1300B sealed) with CEK
  3. MATERIALIZE — Unseal key → Derive shard locations → Fetch ciphertext → Decrypt → Reconstruct

Cryptographic primitives:
  - ML-KEM-768 (FIPS 203 / Kyber) for key encapsulation (sealing lattice keys)
  - ML-DSA-65 (FIPS 204 / Dilithium) for digital signatures (commitment records)
  - BLAKE2b-256 for content-addressing (production: BLAKE3)
  - AEAD (symmetric) for shard encryption and envelope payload encryption

Security properties (Option C + Post-Quantum):
  - Shards encrypted at rest with random Content Encryption Key (CEK)
  - Lattice key sealed via ML-KEM encapsulation (quantum-resistant)
  - Commitment records signed with ML-DSA (quantum-resistant signatures)
  - Shard IDs removed from lattice key (locations derived from entity_id)
  - Commitment log stores only Merkle root (no individual shard metadata)
  - Forward secrecy: each seal() generates a fresh ML-KEM encapsulation
  - Three-leak kill chain CLOSED: key sealed, shards encrypted, log minimal
  - Full post-quantum security: no X25519/Ed25519 dependency

Production dependencies: liboqs or pqcrypto (ML-KEM-768 + ML-DSA-65)
PoC: simulates ML-KEM/ML-DSA API with correct key/ciphertext sizes using
     stdlib BLAKE2b + HMAC. The PoC enforces API semantics and size constraints;
     production replaces simulation with FIPS 203/204 implementations.

Run demo:
  python -m ltp
"""

from .primitives import H, H_bytes, AEAD, MLKEM, MLDSA
from .keypair import KeyPair, KeyRegistry, SealedBox
from .erasure import ErasureCoder
from .shards import ShardEncryptor
from .entity import Entity, canonicalize_shape
from .commitment import (
    AuditResult,
    CommitmentNode,
    CommitmentRecord,
    CommitmentLog,
    CommitmentNetwork,
)
from .lattice import LatticeKey
from .protocol import LTPProtocol


def reset_poc_state() -> None:
    """Reset all PoC simulation state across modules.

    Call this between tests or when you need fresh state. Clears:
      - MLKEM encapsulation lookup tables
      - MLDSA signature lookup tables
      - ShardEncryptor issued CEK tracking set
    """
    MLKEM.reset_poc_state()
    MLDSA.reset_poc_state()
    ShardEncryptor.reset_poc_state()


__all__ = [
    # Primitives
    "H",
    "H_bytes",
    "AEAD",
    "MLKEM",
    "MLDSA",
    # Keypair
    "KeyPair",
    "KeyRegistry",
    "SealedBox",
    # Erasure coding
    "ErasureCoder",
    # Shard encryption
    "ShardEncryptor",
    # Entity
    "Entity",
    "canonicalize_shape",
    # Commitment layer
    "AuditResult",
    "CommitmentNode",
    "CommitmentRecord",
    "CommitmentLog",
    "CommitmentNetwork",
    # Lattice key
    "LatticeKey",
    # Protocol
    "LTPProtocol",
    # Merkle log (CT-style commitment log, §5.1.4)
    "MerkleTree",
    "SignedTreeHead",
    "InclusionProof",
    "MerkleLog",
    # Utilities
    "reset_poc_state",
]


# Lazy imports to avoid circular dependency (merkle_log → ltp.primitives → ltp)
_MERKLE_LOG_NAMES = {"MerkleTree", "SignedTreeHead", "InclusionProof", "MerkleLog"}


def __getattr__(name: str):
    if name in _MERKLE_LOG_NAMES:
        from ..merkle_log import MerkleTree, SignedTreeHead, InclusionProof, MerkleLog
        _map = {
            "MerkleTree": MerkleTree,
            "SignedTreeHead": SignedTreeHead,
            "InclusionProof": InclusionProof,
            "MerkleLog": MerkleLog,
        }
        return _map[name]
    raise AttributeError(f"module 'ltp' has no attribute {name!r}")
