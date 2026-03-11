"""
Cryptographic primitives for the Lattice Transfer Protocol.

Provides:
  - H()       — content-addressing hash (BLAKE2b-256, algorithm-prefixed string)
  - H_bytes() — content-addressing hash (raw 32 bytes, for internal operations)
  - AEAD      — authenticated encryption (PoC: BLAKE2b keystream + HMAC tag)
  - MLKEM     — ML-KEM-768 key encapsulation (PoC simulation, FIPS 203)
  - MLDSA     — ML-DSA-65 digital signatures (PoC simulation, FIPS 204)

Production replacement:
  AEAD  → XChaCha20-Poly1305 (libsodium/NaCl)
  MLKEM → liboqs ML-KEM-768 or FIPS 203 implementation
  MLDSA → liboqs ML-DSA-65 or FIPS 204 implementation
"""

from __future__ import annotations

import collections
import hashlib
import hmac as hmac_mod
import os
import struct
import warnings

__all__ = ["H", "H_bytes", "AEAD", "MLKEM", "MLDSA"]

# Maximum entries in PoC simulation lookup tables before LRU eviction.
# Prevents unbounded memory growth in long-running processes.
_POC_TABLE_MAX = 10_000

warnings.warn(
    "LTP is using PoC cryptographic simulations (BLAKE2b-HMAC). "
    "Do NOT use in production — replace with FIPS 203/204 implementations.",
    stacklevel=1,
)


# ---------------------------------------------------------------------------
# Hash functions
# ---------------------------------------------------------------------------

def H(data: bytes) -> str:
    """Content-addressing hash. Returns 'blake2b:<hex>' (256-bit).

    Canonical format per whitepaper §1.2: algorithm-prefixed hex string.
    Production default is BLAKE3-256; this PoC uses BLAKE2b-256 (identical
    output length and security parameters). Prefix makes the algorithm explicit
    and allows future negotiation of alternatives (e.g., 'blake3:<hex>').
    """
    return "blake2b:" + hashlib.blake2b(data, digest_size=32).hexdigest()


def H_bytes(data: bytes) -> bytes:
    """Content-addressing hash. Returns raw 32 bytes (no prefix).

    Used internally where binary output is required (keystream, nonces, tags).
    """
    return hashlib.blake2b(data, digest_size=32).digest()


# ---------------------------------------------------------------------------
# AEAD: Authenticated Encryption with Associated Data
#
# PoC implementation using BLAKE2b-derived keystream + XOR + HMAC tag.
# Production: XChaCha20-Poly1305 via libsodium/NaCl.
# ---------------------------------------------------------------------------

class AEAD:
    """
    Authenticated encryption for shard-level and envelope-level encryption.

    Provides:
      - Confidentiality: XOR with BLAKE2b-derived keystream
      - Integrity: 32-byte authentication tag (forgery → ValueError)
      - Nonce binding: each (key, nonce) pair produces a unique keystream

    Each shard is encrypted with a nonce derived as H(CEK || entity_id || shard_index)[:16],
    binding nonce uniqueness to both key and entity identity.
    """

    TAG_SIZE = 32  # BLAKE2b-256 authentication tag

    @staticmethod
    def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
        """Generate deterministic keystream: BLAKE2b(key || nonce || counter)."""
        stream = bytearray()
        counter = 0
        while len(stream) < length:
            block = key + nonce + struct.pack('>Q', counter)
            stream.extend(H_bytes(block))
            counter += 1
        return bytes(stream[:length])

    @staticmethod
    def _compute_tag(key: bytes, ciphertext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """Compute authentication tag: BLAKE2b(tag_key || nonce || aad_len || aad || ciphertext)."""
        tag_key = H_bytes(key + b"aead-auth-tag-key")
        aad_len = struct.pack('>Q', len(aad))
        return H_bytes(tag_key + nonce + aad_len + aad + ciphertext)

    @classmethod
    def encrypt(cls, key: bytes, plaintext: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """
        Encrypt plaintext → ciphertext || 32-byte auth tag.

        Args:
            key: 32-byte symmetric key
            plaintext: data to encrypt
            nonce: unique per (key, message) pair
            aad: associated data authenticated but not encrypted
        """
        keystream = cls._keystream(key, nonce, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, keystream))
        tag = cls._compute_tag(key, ciphertext, nonce, aad)
        return ciphertext + tag

    @classmethod
    def decrypt(cls, key: bytes, ciphertext_with_tag: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        """
        Verify tag, then decrypt → plaintext. Raises ValueError if tampered.

        IMPORTANT: Tag is verified BEFORE decryption (authenticate-then-decrypt).
        """
        if len(ciphertext_with_tag) < cls.TAG_SIZE:
            raise ValueError("Ciphertext too short (missing authentication tag)")

        ciphertext = ciphertext_with_tag[:-cls.TAG_SIZE]
        tag = ciphertext_with_tag[-cls.TAG_SIZE:]

        expected_tag = cls._compute_tag(key, ciphertext, nonce, aad)
        if not hmac_mod.compare_digest(tag, expected_tag):
            raise ValueError("AEAD authentication FAILED — data has been tampered with")

        keystream = cls._keystream(key, nonce, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, keystream))


# ---------------------------------------------------------------------------
# ML-KEM-768 (FIPS 203 / Kyber): Key Encapsulation Mechanism
#
# PoC SIMULATION: Uses BLAKE2b to simulate ML-KEM with correct key sizes:
#   - Encapsulation key (ek): 1184 bytes
#   - Decapsulation key (dk): 2400 bytes
#   - Ciphertext: 1088 bytes
#   - Shared secret: 32 bytes
#
# Production: Replace with liboqs ML-KEM-768 or FIPS 203 implementation.
# The PoC enforces size constraints and API semantics; the math is simulated.
# ---------------------------------------------------------------------------

class MLKEM:
    """
    ML-KEM-768 (Kyber) Key Encapsulation Mechanism — PoC simulation.

    Provides:
      - KeyGen() → (encapsulation_key, decapsulation_key)
      - Encaps(ek) → (shared_secret, ciphertext)
      - Decaps(dk, ciphertext) → shared_secret

    Security level: NIST Level 3 (~AES-192 equivalent), quantum-resistant.
    """

    EK_SIZE = 1184   # Encapsulation key size (bytes)
    DK_SIZE = 2400   # Decapsulation key size (bytes)
    CT_SIZE = 1088   # Ciphertext size (bytes)
    SS_SIZE = 32     # Shared secret size (bytes)

    # PoC: maps dk_fingerprint → ek (populated by keygen, LRU-bounded)
    _PoC_dk_to_ek: collections.OrderedDict[str, bytes] = collections.OrderedDict()
    # PoC: maps (ek_fingerprint, ct_hash) → shared_secret (populated by encaps, LRU-bounded)
    _PoC_encaps_table: collections.OrderedDict[tuple[str, str], bytes] = collections.OrderedDict()

    @classmethod
    def keygen(cls) -> tuple[bytes, bytes]:
        """
        Generate an ML-KEM-768 keypair.

        Returns: (encapsulation_key, decapsulation_key)
        The ek is public; dk MUST remain secret.
        """
        seed = os.urandom(64)
        dk_material = bytearray()
        for i in range(0, cls.DK_SIZE, 32):
            dk_material.extend(H_bytes(seed + struct.pack('>I', i) + b"mlkem-dk"))
        dk = bytes(dk_material[:cls.DK_SIZE])

        ek_material = bytearray()
        for i in range(0, cls.EK_SIZE, 32):
            ek_material.extend(H_bytes(seed + struct.pack('>I', i) + b"mlkem-ek"))
        ek = bytes(ek_material[:cls.EK_SIZE])

        # PoC: store dk→ek binding for decapsulation lookup (LRU-bounded)
        dk_fp = H(dk[:32])
        cls._PoC_dk_to_ek[dk_fp] = ek
        if len(cls._PoC_dk_to_ek) > _POC_TABLE_MAX:
            cls._PoC_dk_to_ek.popitem(last=False)

        return ek, dk

    @classmethod
    def encaps(cls, ek: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulate: generate a shared secret and ciphertext.

        Args:
            ek: Encapsulation key (public key of receiver)
        Returns:
            (shared_secret, ciphertext) — ss is 32 bytes, ct is 1088 bytes

        The ciphertext is sent to the receiver; only the holder of dk can
        recover the shared secret from it. Each call produces a FRESH
        (shared_secret, ciphertext) pair — this is the basis for forward secrecy.
        """
        if len(ek) != cls.EK_SIZE:
            raise ValueError(f"Invalid ek size: {len(ek)} (expected {cls.EK_SIZE})")

        ephemeral = os.urandom(32)
        shared_secret = H_bytes(ek + ephemeral + b"mlkem-shared-secret")

        ct_material = bytearray()
        for i in range(0, cls.CT_SIZE, 32):
            ct_material.extend(H_bytes(ek + ephemeral + struct.pack('>I', i) + b"mlkem-ct"))
        ciphertext = bytes(ct_material[:cls.CT_SIZE])

        # PoC: store for decapsulation lookup (LRU-bounded)
        ek_fp = H(ek)
        ct_hash = H(ciphertext)
        cls._PoC_encaps_table[(ek_fp, ct_hash)] = shared_secret
        if len(cls._PoC_encaps_table) > _POC_TABLE_MAX:
            cls._PoC_encaps_table.popitem(last=False)

        return shared_secret, ciphertext

    @classmethod
    def decaps(cls, dk: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate: recover shared secret from ciphertext using dk.

        PoC NOTE: In production ML-KEM, dk mathematically recovers the
        randomness embedded in the ciphertext via lattice decryption.
        The PoC simulates this via SealedBox._PoC_encaps_table.
        """
        if len(dk) != cls.DK_SIZE:
            raise ValueError(f"Invalid dk size: {len(dk)} (expected {cls.DK_SIZE})")
        if len(ciphertext) != cls.CT_SIZE:
            raise ValueError(f"Invalid ct size: {len(ciphertext)} (expected {cls.CT_SIZE})")

        # PoC: recover shared_secret via lookup tables (dk → ek → encaps table)
        dk_fp = H(dk[:32])
        ek = cls._PoC_dk_to_ek.get(dk_fp)
        if ek is None:
            raise ValueError("Cannot decapsulate — unknown decapsulation key")
        ek_fp = H(ek)
        ct_hash = H(ciphertext)
        shared_secret = cls._PoC_encaps_table.get((ek_fp, ct_hash))
        if shared_secret is None:
            raise ValueError(
                "Cannot decapsulate — ciphertext not found "
                "(wrong key or corrupted ciphertext)"
            )
        return shared_secret

    @classmethod
    def reset_poc_state(cls) -> None:
        """Clear PoC simulation state. Call between tests for isolation."""
        cls._PoC_dk_to_ek.clear()
        cls._PoC_encaps_table.clear()


# ---------------------------------------------------------------------------
# ML-DSA-65 (FIPS 204 / Dilithium): Digital Signatures
#
# PoC SIMULATION: Uses BLAKE2b-HMAC to simulate ML-DSA with correct sizes:
#   - Public key (vk): 1952 bytes
#   - Private key (sk): 4032 bytes
#   - Signature: 3309 bytes
#
# Production: Replace with liboqs ML-DSA-65 or FIPS 204 implementation.
# ---------------------------------------------------------------------------

class MLDSA:
    """
    ML-DSA-65 (Dilithium) Digital Signature Algorithm — PoC simulation.

    Provides:
      - KeyGen() → (verification_key, signing_key)
      - Sign(sk, message) → signature
      - Verify(vk, message, signature) → bool

    Security level: NIST Level 3 (~AES-192 equivalent), quantum-resistant.

    PoC simulation note:
      Signature verification uses a lookup table mapping
      (vk_fingerprint, message_hash) → expected_signature.
      keygen() stores the sk→vk binding; sign() stores the signature;
      verify() looks it up. Production replaces this with FIPS 204 math.
    """

    VK_SIZE = 1952   # Verification key (public) size
    SK_SIZE = 4032   # Signing key (private) size
    SIG_SIZE = 3309  # Signature size

    # PoC: maps sk_fingerprint → vk_fingerprint (populated by keygen, LRU-bounded)
    _PoC_sk_to_vk: collections.OrderedDict[str, str] = collections.OrderedDict()
    # PoC: maps (vk_fingerprint, message_hash) → signature (populated by sign, LRU-bounded)
    _PoC_sig_table: collections.OrderedDict[tuple[str, str], bytes] = collections.OrderedDict()

    @classmethod
    def keygen(cls) -> tuple[bytes, bytes]:
        """
        Generate an ML-DSA-65 keypair.

        Returns: (verification_key, signing_key)
        """
        seed = os.urandom(64)

        sk_material = bytearray()
        for i in range(0, cls.SK_SIZE, 32):
            sk_material.extend(H_bytes(seed + struct.pack('>I', i) + b"mldsa-sk"))
        sk = bytes(sk_material[:cls.SK_SIZE])

        vk_material = bytearray()
        for i in range(0, cls.VK_SIZE, 32):
            vk_material.extend(H_bytes(seed + struct.pack('>I', i) + b"mldsa-vk"))
        vk = bytes(vk_material[:cls.VK_SIZE])

        # PoC: store sk→vk binding for signature verification (LRU-bounded)
        sk_fp = H(sk[:32])
        vk_fp = H(vk)
        cls._PoC_sk_to_vk[sk_fp] = vk_fp
        if len(cls._PoC_sk_to_vk) > _POC_TABLE_MAX:
            cls._PoC_sk_to_vk.popitem(last=False)

        return vk, sk

    @classmethod
    def sign(cls, sk: bytes, message: bytes) -> bytes:
        """
        Sign a message with sk.

        Returns: signature (3309 bytes)
        """
        if len(sk) != cls.SK_SIZE:
            raise ValueError(f"Invalid sk size: {len(sk)} (expected {cls.SK_SIZE})")

        raw_sig = H_bytes(sk[:32] + message + b"mldsa-signature")
        sig_material = bytearray()
        for i in range(0, cls.SIG_SIZE, 32):
            sig_material.extend(H_bytes(raw_sig + struct.pack('>I', i) + b"mldsa-expand"))
        signature = bytes(sig_material[:cls.SIG_SIZE])

        # PoC: store for verification lookup (LRU-bounded)
        sk_fp = H(sk[:32])
        vk_fp = cls._PoC_sk_to_vk.get(sk_fp)
        if vk_fp is not None:
            msg_hash = H(message)
            cls._PoC_sig_table[(vk_fp, msg_hash)] = signature
            if len(cls._PoC_sig_table) > _POC_TABLE_MAX:
                cls._PoC_sig_table.popitem(last=False)

        return signature

    @classmethod
    def verify(cls, vk: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verify a signature against vk and message.

        Returns: True if valid, False if forgery/tamper detected.
        """
        if len(vk) != cls.VK_SIZE:
            raise ValueError(f"Invalid vk size: {len(vk)} (expected {cls.VK_SIZE})")
        if len(signature) != cls.SIG_SIZE:
            return False
        vk_fp = H(vk)
        msg_hash = H(message)
        expected = cls._PoC_sig_table.get((vk_fp, msg_hash))
        if expected is None:
            return False
        return hmac_mod.compare_digest(expected, signature)

    @classmethod
    def reset_poc_state(cls) -> None:
        """Clear PoC simulation state. Call between tests for isolation."""
        cls._PoC_sk_to_vk.clear()
        cls._PoC_sig_table.clear()
