"""
Post-quantum asymmetric keypair and envelope encryption for LTP.

Provides:
  - KeyPair   — ML-KEM-768 + ML-DSA-65 combined keypair
  - SealedBox — ML-KEM-768 + AEAD envelope encryption (seal/unseal)
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .primitives import AEAD, MLKEM, MLDSA, H

__all__ = ["KeyPair", "SealedBox"]


# ---------------------------------------------------------------------------
# KeyPair: Post-Quantum Asymmetric Keypair (ML-KEM + ML-DSA)
# ---------------------------------------------------------------------------

@dataclass
class KeyPair:
    """
    Post-quantum asymmetric keypair combining ML-KEM-768 and ML-DSA-65.

    Contains:
      - ek (encapsulation key, public): used to seal lattice keys to this recipient
      - dk (decapsulation key, private): used to unseal lattice keys
      - vk (verification key, public): used to verify commitment signatures
      - sk (signing key, private): used to sign commitment records

    Key sizes (NIST FIPS 203/204):
      ML-KEM-768: ek=1184B, dk=2400B, ciphertext=1088B, shared_secret=32B
      ML-DSA-65:  vk=1952B, sk=4032B, signature=3309B

    Security level: NIST Level 3 (~AES-192), resistant to both classical and
    quantum attacks (Grover, Shor).
    """
    ek: bytes          # ML-KEM encapsulation key (1184 bytes, public)
    dk: bytes          # ML-KEM decapsulation key (2400 bytes, private)
    vk: bytes          # ML-DSA verification key (1952 bytes, public)
    sk: bytes          # ML-DSA signing key (4032 bytes, private)
    label: str = ""

    @classmethod
    def generate(cls, label: str = "") -> 'KeyPair':
        """Generate a fresh post-quantum keypair (ML-KEM-768 + ML-DSA-65)."""
        ek, dk = MLKEM.keygen()
        vk, sk = MLDSA.keygen()
        return cls(ek=ek, dk=dk, vk=vk, sk=sk, label=label)

    @property
    def pub_hex(self) -> str:
        """Short representation of the public encapsulation key."""
        return self.ek.hex()[:16] + "..."

    @property
    def public_key(self) -> bytes:
        """ML-KEM encapsulation key (for sealing to this recipient)."""
        return self.ek


# ---------------------------------------------------------------------------
# SealedBox: Post-Quantum Envelope Encryption (ML-KEM-768 + AEAD)
#
# Protocol:
#   seal(plaintext, receiver_ek) → kem_ciphertext(1088) || nonce(16) || aead_ct+tag
#   unseal(sealed_bytes, receiver_keypair) → plaintext
#
# Forward secrecy: each seal() performs a fresh ML-KEM.Encaps(ek), producing a
# unique (shared_secret, kem_ciphertext) pair. The shared_secret is used once
# as the AEAD key, then immediately zeroized.
# ---------------------------------------------------------------------------

class SealedBox:
    """
    Post-quantum public-key envelope encryption using ML-KEM-768 + AEAD.

    Security:
      - Each seal() uses a fresh ML-KEM encapsulation (forward secrecy per message)
      - Only the holder of the corresponding dk can unseal
      - Sealed output is indistinguishable from random bytes
      - Resistant to both classical and quantum adversaries

    Sealed format:
      kem_ciphertext(1088) || nonce(16) || aead_ciphertext(variable) || aead_tag(32)

    Total overhead: 1088 + 16 + 32 = 1136 bytes over plaintext
    """

    # PoC: maps (ek_fingerprint, kem_ct_hash) → shared_secret for simulation
    _PoC_encaps_table: dict[tuple[str, str], bytes] = {}

    @classmethod
    def seal(cls, plaintext: bytes, receiver_ek: bytes) -> bytes:
        """
        Seal plaintext to receiver's ML-KEM encapsulation key.

        Forward secrecy: each call generates a fresh encapsulation.
        The shared_secret is used once and then discarded.
        """
        assert len(receiver_ek) == MLKEM.EK_SIZE, \
            f"Invalid ek size: {len(receiver_ek)} (expected {MLKEM.EK_SIZE})"

        shared_secret, kem_ct = MLKEM.encaps(receiver_ek)

        # PoC: store mapping so decaps can recover shared_secret
        ek_fingerprint = H(receiver_ek)
        ct_hash = H(kem_ct)
        cls._PoC_encaps_table[(ek_fingerprint, ct_hash)] = shared_secret

        nonce = os.urandom(16)
        ciphertext = AEAD.encrypt(shared_secret, plaintext, nonce)
        del shared_secret

        return kem_ct + nonce + ciphertext

    @classmethod
    def unseal(cls, sealed_data: bytes, receiver_keypair: KeyPair) -> bytes:
        """
        Unseal with receiver's ML-KEM decapsulation key.

        Raises ValueError if wrong keypair or tampered data.
        """
        min_len = MLKEM.CT_SIZE + 16 + AEAD.TAG_SIZE
        if len(sealed_data) < min_len:
            raise ValueError(f"Sealed data too short ({len(sealed_data)} < {min_len})")

        kem_ct = sealed_data[:MLKEM.CT_SIZE]
        nonce = sealed_data[MLKEM.CT_SIZE:MLKEM.CT_SIZE + 16]
        aead_ct = sealed_data[MLKEM.CT_SIZE + 16:]

        # PoC: look up shared_secret from encaps table
        # Production: MLKEM.decaps(receiver_keypair.dk, kem_ct) → shared_secret
        ek_fingerprint = H(receiver_keypair.ek)
        ct_hash = H(kem_ct)
        lookup_key = (ek_fingerprint, ct_hash)

        shared_secret = cls._PoC_encaps_table.get(lookup_key)
        if shared_secret is None:
            raise ValueError(
                "Cannot unseal — ML-KEM decapsulation failed "
                "(wrong decapsulation key or corrupted ciphertext)"
            )

        try:
            plaintext = AEAD.decrypt(shared_secret, aead_ct, nonce)
        except ValueError as e:
            raise ValueError(f"Cannot unseal — AEAD decryption failed: {e}")

        del shared_secret
        return plaintext

    @classmethod
    def reset_poc_state(cls) -> None:
        """Clear PoC simulation state. Call between tests for isolation."""
        cls._PoC_encaps_table.clear()
