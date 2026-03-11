"""
Commitment layer for the Lattice Transfer Protocol.

Provides:
  - AuditResult       — typed result of a node audit challenge
  - CommitmentNode    — distributed node storing encrypted shards
  - CommitmentRecord  — minimal log entry (ML-DSA signed, Merkle root only)
  - CommitmentLog     — append-only hash-chained ledger with inclusion proofs
  - CommitmentNetwork — orchestrates nodes, log, audit, and placement
"""

from __future__ import annotations

import json
import os
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

from .primitives import H, H_bytes, MLDSA

__all__ = [
    "AuditResult",
    "CommitmentNode",
    "CommitmentRecord",
    "CommitmentLog",
    "CommitmentNetwork",
]


# ---------------------------------------------------------------------------
# AuditResult: typed return value for node audit operations
# ---------------------------------------------------------------------------

@dataclass
class AuditResult:
    """Result of a storage-proof audit on a single commitment node."""
    node_id: str
    challenged: int
    passed: int
    failed: int
    missing: int
    suspicious_latency: int
    burst_size: int
    avg_response_us: float
    result: str        # "PASS" or "FAIL"
    strikes: int


# ---------------------------------------------------------------------------
# CommitmentNode
# ---------------------------------------------------------------------------

class CommitmentNode:
    """
    A node in the distributed commitment network.

    SECURITY (Option C):
      - Stores ONLY encrypted shard data (ciphertext)
      - Keyed by (entity_id, shard_index) — both derivable by authorized receivers
      - Cannot read shard content (no access to CEK)
    """

    def __init__(self, node_id: str, region: str) -> None:
        self.node_id = node_id
        self.region = region
        self.shards: dict[tuple[str, int], bytes] = {}
        self.strikes: int = 0
        self.audit_passes: int = 0
        self.evicted: bool = False

    def store_shard(self, entity_id: str, shard_index: int, encrypted_data: bytes) -> bool:
        """Store an encrypted shard. Returns False if node is evicted."""
        if self.evicted:
            return False
        self.shards[(entity_id, shard_index)] = encrypted_data
        return True

    def fetch_shard(self, entity_id: str, shard_index: int) -> Optional[bytes]:
        """Fetch an encrypted shard. Returns None if missing or evicted."""
        if self.evicted:
            return None
        return self.shards.get((entity_id, shard_index))

    def respond_to_audit(
        self, entity_id: str, shard_index: int, nonce: bytes
    ) -> Optional[str]:
        """
        Respond to a storage proof challenge.

        Protocol: Challenge(entity_id, shard_index, nonce) → H(ciphertext || nonce)
        Returns None if the shard is missing (audit failure).
        """
        if self.evicted:
            return None
        ct = self.shards.get((entity_id, shard_index))
        if ct is None:
            return None
        return H(ct + nonce)

    def remove_shard(self, entity_id: str, shard_index: int) -> bool:
        """Remove a shard (used to simulate node failure or eviction cleanup)."""
        key = (entity_id, shard_index)
        if key in self.shards:
            del self.shards[key]
            return True
        return False

    @property
    def shard_count(self) -> int:
        return len(self.shards)


# ---------------------------------------------------------------------------
# CommitmentRecord
# ---------------------------------------------------------------------------

@dataclass
class CommitmentRecord:
    """
    An immutable record in the commitment log.

    SECURITY (Option C + Post-Quantum):
      - Individual shard IDs are NOT stored
      - Only a Merkle root of encrypted shard hashes is stored
      - Signed with ML-DSA-65 (quantum-resistant digital signature)
    """
    entity_id: str
    sender_id: str
    shard_map_root: str       # H(H(enc_shard_0) || ... || H(enc_shard_n))
    content_hash: str         # H(content) — secondary integrity check
    encoding_params: dict     # {"n", "k", "algorithm", "gf_poly", "eval"}
    shape: str                # canonicalized media type
    shape_hash: str           # H(shape) — legacy lookup compatibility
    timestamp: float
    predecessor: Optional[str] = None
    signature: bytes = b""    # ML-DSA-65 signature (3309 bytes)

    def signable_payload(self) -> bytes:
        """Deterministic binary encoding of the fields that get signed/verified.

        Uses struct-packed binary encoding instead of JSON to avoid
        cross-implementation float serialization differences (e.g.,
        1234567890.123 vs 1.234567890123e+09).  Each field is
        length-prefixed (4-byte big-endian) except the fixed-size timestamp
        (8-byte IEEE 754 double, big-endian).

        NOTE: `predecessor` is intentionally excluded. It is set by
        CommitmentLog.append() after signing, so including it would
        invalidate the signature. The sender authenticates the commitment
        content; the log's Merkle tree separately authenticates ordering.
        """
        parts: list[bytes] = []
        for s in (self.entity_id, self.sender_id, self.shard_map_root,
                  self.content_hash, self.shape, self.shape_hash):
            raw = s.encode()
            parts.append(struct.pack('>I', len(raw)) + raw)
        # Timestamp as fixed-width IEEE 754 double (deterministic across languages)
        parts.append(struct.pack('>d', self.timestamp))
        # Encoding params: sorted key-value pairs, each length-prefixed
        ep = self.encoding_params
        for k in sorted(ep.keys()):
            kb = k.encode()
            vb = str(ep[k]).encode()
            parts.append(struct.pack('>I', len(kb)) + kb)
            parts.append(struct.pack('>I', len(vb)) + vb)
        return b"LTP-COMMIT-v1\x00" + b"".join(parts)

    def sign(self, sender_sk: bytes) -> None:
        """Sign this record with the sender's ML-DSA-65 signing key."""
        self.signature = MLDSA.sign(sender_sk, self.signable_payload())

    def verify_signature(self, sender_vk: bytes) -> bool:
        """Verify this record's ML-DSA-65 signature against sender's vk."""
        if not self.signature:
            return False
        return MLDSA.verify(sender_vk, self.signable_payload(), self.signature)

    def to_bytes(self) -> bytes:
        """Deterministic binary encoding of the full record (including signature).

        Used for Merkle log leaves and commitment_ref computation.  Includes
        all fields — predecessor and signature — unlike signable_payload()
        which excludes them.
        """
        parts: list[bytes] = [self.signable_payload()]
        # Predecessor (may be None before log appends it)
        pred = (self.predecessor or "").encode()
        parts.append(struct.pack('>I', len(pred)) + pred)
        # Signature
        parts.append(struct.pack('>I', len(self.signature)) + self.signature)
        return b"LTP-RECORD-v1\x00" + b"".join(parts)

    def to_dict(self) -> dict:
        return {
            "entity_id": self.entity_id,
            "sender_id": self.sender_id,
            "shard_map_root": self.shard_map_root,
            "content_hash": self.content_hash,
            "encoding_params": self.encoding_params,
            "shape": self.shape,
            "shape_hash": self.shape_hash,
            "timestamp": self.timestamp,
            "predecessor": self.predecessor,
            "signature": self.signature.hex() if self.signature else "",
        }


# ---------------------------------------------------------------------------
# CommitmentLog
# ---------------------------------------------------------------------------

class CommitmentLog:
    """
    CT-style append-only commitment log backed by a MerkleLog (§5.1.4).

    Wraps a MerkleLog (RFC 6962 Merkle tree + ML-DSA-65 Signed Tree Heads)
    with entity_id-based indexing for the protocol layer.

    Security properties:
      - Append-only Merkle tree: RFC 6962 domain-separated leaves/nodes
      - ML-DSA-65 Signed Tree Heads: operator-signed snapshots after each append
      - O(log N) inclusion proofs: verify record membership without full log
      - O(log N) consistency proofs: verify append-only invariant between snapshots
      - Fork detection: inconsistent STHs are cryptographic proof of equivocation
    """

    def __init__(self) -> None:
        from .keypair import KeyPair
        from ..merkle_log import MerkleLog
        self._operator_kp = KeyPair.generate("log-operator")
        self._merkle_log = MerkleLog(
            self._operator_kp.vk, self._operator_kp.sk,
        )
        self._records: dict[str, CommitmentRecord] = {}
        self._chain: list[str] = []  # ordered entity_ids (used by audit)
        self._record_indices: dict[str, int] = {}  # entity_id → leaf index

    def append(self, record: CommitmentRecord) -> str:
        """
        Append a record to the Merkle log. Returns its commitment reference.

        The record is serialized to deterministic binary encoding, appended to
        the MerkleLog, and an STH is published covering the new tree state.
        """
        if record.entity_id in self._records:
            raise ValueError(f"Entity {record.entity_id} already committed (immutable)")

        record.predecessor = self.head_hash

        record_bytes = record.to_bytes()
        record_hash = H(record_bytes)
        idx = self._merkle_log.append(record_bytes)
        self._merkle_log.publish_sth()

        self._records[record.entity_id] = record
        self._chain.append(record.entity_id)
        self._record_indices[record.entity_id] = idx

        return record_hash

    def fetch(self, entity_id: str) -> Optional[CommitmentRecord]:
        return self._records.get(entity_id)

    def verify_chain_integrity(self) -> tuple[bool, int]:
        """
        Verify the entire log against the Merkle tree.

        Re-serializes each in-memory record and checks that its leaf hash
        matches the tree.  Detects in-memory tampering (e.g., modified
        content_hash after commit).

        Returns: (is_valid, last_valid_index)
        """
        from ..merkle_log.tree import _leaf_hash
        if not self._chain:
            return True, -1
        for i, entity_id in enumerate(self._chain):
            record = self._records[entity_id]
            record_bytes = record.to_bytes()
            expected = _leaf_hash(record_bytes)
            stored = self._merkle_log._tree.leaf_hash(i)
            if expected != stored:
                return False, i
        return True, len(self._chain) - 1

    def get_inclusion_proof(self, entity_id: str) -> Optional[dict]:
        """Generate an O(log N) Merkle inclusion proof for a committed entity."""
        if entity_id not in self._records:
            return None
        idx = self._record_indices[entity_id]
        proof = self._merkle_log.inclusion_proof(idx)
        return {
            "entity_id": entity_id,
            "position": idx,
            "inclusion_proof": proof,
            "root_hash": proof.root_hash,
        }

    def verify_inclusion(self, entity_id: str, proof: dict) -> bool:
        """Verify an O(log N) inclusion proof against the current root."""
        record = self._records.get(entity_id)
        if record is None:
            return False
        record_bytes = record.to_bytes()
        inc_proof = proof["inclusion_proof"]
        return inc_proof.verify(record_bytes, proof["root_hash"])

    @property
    def head_hash(self) -> str:
        """Current Merkle root hash as a hex string."""
        sth = self._merkle_log.latest_sth
        if sth is None:
            return "0" * 64
        return sth.root_hash.hex()

    @property
    def length(self) -> int:
        return self._merkle_log.size

    @property
    def latest_sth(self):
        """Most recently published Signed Tree Head."""
        return self._merkle_log.latest_sth

    @property
    def merkle_log(self):
        """Access to the underlying MerkleLog for advanced operations."""
        return self._merkle_log


# ---------------------------------------------------------------------------
# CommitmentNetwork
# ---------------------------------------------------------------------------

class CommitmentNetwork:
    """
    Manages the distributed commitment network.

    Responsibilities:
      - Deterministic shard placement via consistent hashing
      - Distributing and fetching encrypted shards
      - Storage proof auditing with burst challenges
      - Node eviction and shard repair
      - Correlated failure analysis (regional failure model)
    """

    def __init__(self) -> None:
        self.nodes: list[CommitmentNode] = []
        self.log = CommitmentLog()

    def add_node(self, node_id: str, region: str) -> CommitmentNode:
        node = CommitmentNode(node_id, region)
        self.nodes.append(node)
        return node

    def _placement(
        self, entity_id: str, shard_index: int, replicas: int = 2
    ) -> list[CommitmentNode]:
        """Deterministic shard placement via consistent hashing.

        Uses rehashing to avoid the stride-based clustering problem:
        each replica slot gets a unique hash derived from the placement
        key and replica index, producing uniform distribution regardless
        of network size.
        """
        if not self.nodes:
            raise ValueError("No commitment nodes available")

        active = [n for n in self.nodes if not n.evicted]
        if not active:
            raise ValueError("No active commitment nodes available")

        n_active = len(active)
        selected: list[CommitmentNode] = []

        for r in range(replicas):
            placement_key = f"{entity_id}:{shard_index}:{r}"
            h = int.from_bytes(H_bytes(placement_key.encode()), "big")
            idx = h % n_active
            candidate = active[idx]
            if candidate not in selected:
                selected.append(candidate)
            elif n_active > len(selected):
                # Rehash to find an unselected node
                for attempt in range(n_active):
                    rehash_key = f"{placement_key}:{attempt}"
                    rh = int.from_bytes(H_bytes(rehash_key.encode()), "big")
                    candidate = active[rh % n_active]
                    if candidate not in selected:
                        selected.append(candidate)
                        break

        return selected

    def distribute_encrypted_shards(
        self, entity_id: str, encrypted_shards: list[bytes], replicas: int = 2
    ) -> str:
        """
        Distribute encrypted shards to commitment nodes.

        Returns: Merkle root of encrypted shard hashes (RFC 6962 tree).

        The shard Merkle tree uses the same domain-separated hashing as the
        commitment log (0x00 leaf prefix, 0x01 internal prefix), enabling
        O(log n) per-shard inclusion proofs against the commitment record.
        """
        from ..merkle_log.tree import MerkleTree

        shard_tree = MerkleTree()
        for i, enc_shard in enumerate(encrypted_shards):
            shard_data = enc_shard + entity_id.encode() + struct.pack('>I', i)
            shard_tree.append(shard_data)

            target_nodes = self._placement(entity_id, i, replicas)
            for node in target_nodes:
                node.store_shard(entity_id, i, enc_shard)

        return H(shard_tree.root())

    def fetch_encrypted_shards(
        self, entity_id: str, n: int, max_shards: int
    ) -> dict[int, bytes]:
        """
        Fetch up to *max_shards* encrypted shards by deriving locations from entity_id.

        Iterates through shard indices 0..n-1 and stops early once *max_shards*
        have been collected. Callers typically pass max_shards=n to fetch all
        available shards, or max_shards=k to fetch the minimum needed for
        erasure decoding.

        NO shard_ids needed — locations computed from entity_id + index.
        Returns: {shard_index: encrypted_shard_bytes}
        """
        fetched: dict[int, bytes] = {}

        for i in range(n):
            if len(fetched) >= max_shards:
                break
            target_nodes = self._placement(entity_id, i)
            for node in target_nodes:
                data = node.fetch_shard(entity_id, i)
                if data is not None:
                    fetched[i] = data
                    break

        return fetched

    def audit_node(self, node: CommitmentNode, burst: int = 1) -> AuditResult:
        """
        Audit a single node via storage proof challenges.

        Anti-outsourcing: burst challenges issue `burst` simultaneous nonces
        per shard, multiplying relay latency and making outsourcing detectable.

        Returns: AuditResult with full challenge statistics.
        """
        challenged = 0
        passed = 0
        failed = 0
        missing = 0
        suspicious_latency = 0
        response_times: list[float] = []

        for entity_id in self.log._chain:
            record = self.log.fetch(entity_id)
            if record is None:
                continue
            n = record.encoding_params.get("n", 8)
            for shard_index in range(n):
                target_nodes = self._placement(entity_id, shard_index)
                if node not in target_nodes:
                    continue

                nonces = [os.urandom(16) for _ in range(burst)]
                burst_pass = True

                for nonce in nonces:
                    t0 = time.monotonic()
                    response = node.respond_to_audit(entity_id, shard_index, nonce)
                    elapsed = time.monotonic() - t0
                    response_times.append(elapsed)
                    challenged += 1

                    if response is None:
                        missing += 1
                        failed += 1
                        burst_pass = False
                    else:
                        known_good = self._get_known_good_hash(
                            entity_id, shard_index, nonce, exclude_node=node
                        )
                        if known_good is not None and response == known_good:
                            passed += 1
                        elif known_good is None:
                            passed += 1
                        else:
                            failed += 1
                            burst_pass = False

                if burst > 1 and burst_pass and response_times:
                    burst_latencies = response_times[-burst:]
                    max_burst_latency = max(burst_latencies)
                    if max_burst_latency > 0.001:
                        suspicious_latency += 1

        if challenged == 0:
            result = "PASS"
        elif failed > 0:
            result = "FAIL"
            node.strikes += 1
        else:
            result = "PASS"
            node.audit_passes += 1
            node.strikes = max(0, node.strikes - 1)

        avg_latency = (sum(response_times) / len(response_times)) if response_times else 0.0

        return AuditResult(
            node_id=node.node_id,
            challenged=challenged,
            passed=passed,
            failed=failed,
            missing=missing,
            suspicious_latency=suspicious_latency,
            burst_size=burst,
            avg_response_us=round(avg_latency * 1_000_000, 1),
            result=result,
            strikes=node.strikes,
        )

    def _get_known_good_hash(
        self, entity_id: str, shard_index: int, nonce: bytes,
        exclude_node: CommitmentNode
    ) -> Optional[str]:
        """Fetch a known-good audit hash from another healthy replica."""
        for other_node in self.nodes:
            if other_node is exclude_node or other_node.evicted:
                continue
            response = other_node.respond_to_audit(entity_id, shard_index, nonce)
            if response is not None:
                return response
        return None

    def audit_all_nodes(self, burst: int = 1) -> list[AuditResult]:
        """Audit every active node. Returns list of AuditResult."""
        results = []
        for node in self.nodes:
            if not node.evicted:
                results.append(self.audit_node(node, burst=burst))
        return results

    def evict_node(self, node: CommitmentNode) -> dict:
        """
        Evict a misbehaving node and trigger shard repair.

        Repair operates on CIPHERTEXT — no plaintext exposure.
        Returns: {"evicted_node", "shards_affected", "repaired", "lost"}
        """
        node.evicted = True
        repaired = 0
        lost = 0

        orphaned_shards = list(node.shards.items())

        for (entity_id, shard_index), enc_shard in orphaned_shards:
            replica_found = False
            for other_node in self.nodes:
                if other_node is node or other_node.evicted:
                    continue
                replica = other_node.fetch_shard(entity_id, shard_index)
                if replica is not None:
                    for target in self.nodes:
                        if (target is not node and not target.evicted
                                and target.fetch_shard(entity_id, shard_index) is None):
                            target.store_shard(entity_id, shard_index, replica)
                            repaired += 1
                            replica_found = True
                            break
                    if replica_found:
                        break
            if not replica_found:
                lost += 1

        return {
            "evicted_node": node.node_id,
            "shards_affected": len(orphaned_shards),
            "repaired": repaired,
            "lost": lost,
        }

    @property
    def active_node_count(self) -> int:
        return sum(1 for n in self.nodes if not n.evicted)

    # --- Correlated Failure Analysis (Whitepaper §5.4.1.1) ---

    def region_failure(self, region: str) -> list[CommitmentNode]:
        """Simulate correlated regional failure. Returns affected nodes."""
        affected = []
        for node in self.nodes:
            if node.region == region and not node.evicted:
                node.evicted = True
                affected.append(node)
        return affected

    def restore_region(self, region: str) -> list[CommitmentNode]:
        """Restore all nodes in a region (undo region_failure)."""
        restored = []
        for node in self.nodes:
            if node.region == region and node.evicted:
                node.evicted = False
                restored.append(node)
        return restored

    def check_cross_region_placement(
        self, entity_id: str, n: int, replicas: int = 2
    ) -> dict:
        """
        Verify that shard replicas span multiple failure domains (regions).

        Returns: {"entity_id", "total_shards", "cross_region_count",
                  "same_region_count", "regions_used", "all_cross_region"}
        """
        cross_region = 0
        same_region = 0
        regions_used: set[str] = set()

        for shard_index in range(n):
            targets = self._placement(entity_id, shard_index, replicas)
            target_regions = {t.region for t in targets}
            regions_used |= target_regions
            if len(target_regions) > 1:
                cross_region += 1
            else:
                same_region += 1

        return {
            "entity_id": entity_id[:16] + "...",
            "total_shards": n,
            "cross_region_count": cross_region,
            "same_region_count": same_region,
            "regions_used": sorted(regions_used),
            "all_cross_region": same_region == 0,
        }

    def availability_under_region_failure(
        self, entity_id: str, n: int, k: int, failed_region: str
    ) -> dict:
        """
        Compute shard availability if an entire region fails.

        Returns: {"failed_region", "shards_total", "shards_lost",
                  "shards_surviving", "can_reconstruct", "k_threshold"}
        """
        surviving = 0
        lost = 0
        for shard_index in range(n):
            targets = self._placement(entity_id, shard_index)
            has_survivor = any(
                t.region != failed_region and not t.evicted
                for t in targets
            )
            if has_survivor:
                surviving += 1
            else:
                lost += 1

        return {
            "failed_region": failed_region,
            "shards_total": n,
            "shards_lost": lost,
            "shards_surviving": surviving,
            "can_reconstruct": surviving >= k,
            "k_threshold": k,
        }
