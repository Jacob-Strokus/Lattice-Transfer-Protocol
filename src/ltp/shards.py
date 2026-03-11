"""
Shard encryption/decryption for the Lattice Transfer Protocol.

Provides:
  - ShardEncryptor — encrypt/decrypt individual shards using a CEK

Nonce derivation: nonce_i = H(CEK || entity_id || shard_index)[:16]
This binds the nonce to both key and entity identity, providing defense-in-depth
against CSPRNG failures and CEK reuse across entities.
"""

from __future__ import annotations

import os
import struct

from .primitives import AEAD, H_bytes

__all__ = ["ShardEncryptor"]


class ShardEncryptor:
    """
    Encrypts/decrypts individual shards using the Content Encryption Key (CEK).

    SECURITY INVARIANT — Nonce Derivation:
      nonce_i = H(CEK || entity_id || shard_index)[:16]

      Binds nonce to both CEK and entity_id, ensuring that even if a CEK is
      accidentally reused across entities, the nonces diverge because entity_id
      differs. CEK uniqueness (via CSPRNG) remains the primary barrier; nonce
      derivation is an additional layer of defense.

    CEK uniqueness invariant:
      Each entity MUST have a unique CEK. Since AEAD nonces are derived from
      shard_index, CEK uniqueness is the sole barrier against catastrophic
      nonce reuse. generate_cek() uses os.urandom (CSPRNG) and checks for
      degenerate values. See whitepaper §2.1.1.
    """

    # Track issued CEKs within this process to detect accidental reuse.
    _issued_ceks: set[bytes] = set()

    @classmethod
    def generate_cek(cls) -> bytes:
        """Generate a random 256-bit Content Encryption Key from CSPRNG.

        Raises RuntimeError if the generated key collides with a previously
        issued CEK (probability ~2^{-256} — detection is defense-in-depth).
        """
        cek = os.urandom(32)
        if cek in cls._issued_ceks:
            raise RuntimeError(
                "CRITICAL: CEK collision detected — CSPRNG may be compromised. "
                "Aborting to prevent catastrophic nonce reuse."
            )
        cls._issued_ceks.add(cek)
        return cek

    @classmethod
    def validate_cek(cls, cek: bytes) -> None:
        """Validate a CEK meets security requirements (length, non-degenerate)."""
        if not isinstance(cek, bytes) or len(cek) != 32:
            raise ValueError(
                f"CEK must be exactly 32 bytes, got "
                f"{len(cek) if isinstance(cek, bytes) else type(cek).__name__}"
            )
        if cek == b'\x00' * 32:
            raise ValueError("CEK is all-zero — degenerate key rejected")
        if cek == b'\xff' * 32:
            raise ValueError("CEK is all-one — degenerate key rejected")

    @staticmethod
    def _nonce(cek: bytes, entity_id: str, shard_index: int) -> bytes:
        """Deterministic 16-byte nonce: H(CEK || entity_id || shard_index)[:16].

        Matches whitepaper §2.1.1 nonce derivation specification.
        """
        index_bytes = struct.pack('>I', shard_index)
        digest = H_bytes(cek + entity_id.encode() + index_bytes)
        return digest[:16]

    @staticmethod
    def _aad(entity_id: str, shard_index: int) -> bytes:
        """Associated data binding entity_id and shard_index into the AEAD tag.

        This explicitly authenticates shard identity alongside the nonce derivation,
        providing defense-in-depth: even if the nonce were somehow reused, the AAD
        prevents cross-entity or cross-index shard substitution.
        """
        return entity_id.encode() + struct.pack('>I', shard_index)

    @classmethod
    def encrypt_shard(
        cls, cek: bytes, entity_id: str, plaintext_shard: bytes, shard_index: int
    ) -> bytes:
        """Encrypt a shard with CEK. Returns ciphertext || 32-byte auth tag."""
        cls.validate_cek(cek)
        nonce = cls._nonce(cek, entity_id, shard_index)
        aad = cls._aad(entity_id, shard_index)
        return AEAD.encrypt(cek, plaintext_shard, nonce, aad)

    @classmethod
    def decrypt_shard(
        cls, cek: bytes, entity_id: str, encrypted_shard: bytes, shard_index: int
    ) -> bytes:
        """Decrypt a shard with CEK. Raises ValueError if tampered."""
        nonce = cls._nonce(cek, entity_id, shard_index)
        aad = cls._aad(entity_id, shard_index)
        return AEAD.decrypt(cek, encrypted_shard, nonce, aad)

    @classmethod
    def reset_poc_state(cls) -> None:
        """Clear PoC simulation state. Call between tests for isolation."""
        cls._issued_ceks.clear()
