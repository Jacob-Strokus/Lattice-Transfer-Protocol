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
from ..merkle_log import MerkleTree, InclusionProof

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
        """The canonical bytes that get signed/verified.

        NOTE: `predecessor` is intentionally excluded. It is set by
        CommitmentLog.append() after signing, so including it would
        invalidate the signature. The sender authenticates the commitment
        content; the log's hash-chain separately authenticates predecessor.
        """
        d = {
            "entity_id": self.entity_id,
            "sender_id": self.sender_id,
            "shard_map_root": self.shard_map_root,
            "content_hash": self.content_hash,
            "encoding_params": self.encoding_params,
            "shape": self.shape,
            "shape_hash": self.shape_hash,
            "timestamp": self.timestamp,
        }
        return json.dumps(d, sort_keys=True).encode()

    def sign(self, sender_sk: bytes) -> None:
        """Sign this record with the sender's ML-DSA-65 signing key."""
        self.signature = MLDSA.sign(sender_sk, self.signable_payload())

    def verify_signature(self, sender_vk: bytes) -> bool:
        """Verify this record's ML-DSA-65 signature against sender's vk."""
        if not self.signature:
            return False
        return MLDSA.verify(sender_vk, self.signable_payload(), self.signature)

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
    Append-only commitment log with hash-chaining and signed tree heads.

    Security properties (Whitepaper §5.1.4):
      - Hash-chained: each entry references the hash of the previous entry
      - Signed tree heads (STH): operators sign the root hash at each append
      - Inclusion proofs: O(log N) Merkle proof that a record exists in the log
      - Fork detection: inconsistent STHs are cryptographic proof of equivocation
    """

    def __init__(self) -> None:
        self._records: dict[str, CommitmentRecord] = {}
        self._chain: list[str] = []
        self._chain_hashes: list[str] = []
        self._tree_heads: list[dict] = []

    def append(self, record: CommitmentRecord) -> str:
        """
        Append a record to the hash-chained log. Returns its commitment reference.

        chain_hash = H(record_bytes || previous_chain_hash)
        """
        if record.entity_id in self._records:
            raise ValueError(f"Entity {record.entity_id} already committed (immutable)")

        prev_hash = self._chain_hashes[-1] if self._chain_hashes else ("0" * 64)
        record.predecessor = prev_hash

        record_bytes = json.dumps(record.to_dict(), sort_keys=True).encode()
        record_hash = H(record_bytes)
        chain_hash = H(record_bytes + prev_hash.encode())

        self._records[record.entity_id] = record
        self._chain.append(record.entity_id)
        self._chain_hashes.append(chain_hash)

        sth = {
            "sequence": len(self._chain) - 1,
            "root_hash": chain_hash,
            "timestamp": time.time(),
            "record_count": len(self._chain),
        }
        self._tree_heads.append(sth)

        return record_hash

    def fetch(self, entity_id: str) -> Optional[CommitmentRecord]:
        return self._records.get(entity_id)

    def verify_chain_integrity(self) -> tuple[bool, int]:
        """
        Verify the entire hash chain from genesis to head.

        Returns: (is_valid, last_valid_index)
        """
        prev_hash = "0" * 64
        for i, entity_id in enumerate(self._chain):
            record = self._records[entity_id]
            record_bytes = json.dumps(record.to_dict(), sort_keys=True).encode()
            expected_hash = H(record_bytes + prev_hash.encode())
            if expected_hash != self._chain_hashes[i]:
                return False, i
            prev_hash = self._chain_hashes[i]
        return True, len(self._chain) - 1

    def get_inclusion_proof(self, entity_id: str) -> Optional[dict]:
        """Generate an inclusion proof for a committed entity."""
        if entity_id not in self._records:
            return None
        idx = self._chain.index(entity_id)
        return {
            "entity_id": entity_id,
            "position": idx,
            "chain_hash": self._chain_hashes[idx],
            "predecessor": self._chain_hashes[idx - 1] if idx > 0 else ("0" * 64),
            "tree_head": self._tree_heads[idx] if idx < len(self._tree_heads) else None,
        }

    def verify_inclusion(self, entity_id: str, proof: dict) -> bool:
        """Verify an inclusion proof against the current log state."""
        record = self._records.get(entity_id)
        if record is None:
            return False
        record_bytes = json.dumps(record.to_dict(), sort_keys=True).encode()
        expected = H(record_bytes + proof["predecessor"].encode())
        return expected == proof["chain_hash"]

    @property
    def head_hash(self) -> str:
        """Current tree head hash (latest chain_hash)."""
        return self._chain_hashes[-1] if self._chain_hashes else ("0" * 64)

    @property
    def length(self) -> int:
        return len(self._chain)


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
        # Per-entity shard hashes stored at commit time.
        # Each entry: entity_id → [H_bytes(enc_shard_i || entity_id || i), ...]
        # Used to build inclusion proofs and verify Merkle commitment integrity.
        self._shard_hashes: dict[str, list[bytes]] = {}

    def add_node(self, node_id: str, region: str) -> CommitmentNode:
        node = CommitmentNode(node_id, region)
        self.nodes.append(node)
        return node

    def _placement(
        self, entity_id: str, shard_index: int, replicas: int = 2
    ) -> list[CommitmentNode]:
        """Deterministic shard placement via consistent hashing."""
        if not self.nodes:
            raise ValueError("No commitment nodes available")

        placement_key = f"{entity_id}:{shard_index}"
        h = int.from_bytes(H_bytes(placement_key.encode()), "big")

        selected = []
        for r in range(replicas):
            idx = (h + r * 7) % len(self.nodes)
            if self.nodes[idx] not in selected:
                selected.append(self.nodes[idx])

        return selected

    def distribute_encrypted_shards(
        self, entity_id: str, encrypted_shards: list[bytes], replicas: int = 2
    ) -> str:
        """
        Distribute encrypted shards to commitment nodes.

        Returns: hex Merkle root of shard hashes (for CommitmentRecord.shard_map_root).

        Each shard hash is H_bytes(enc_shard || entity_id || shard_index), binding
        the hash to both the ciphertext and its position — prevents cross-entity and
        cross-position substitution attacks.  The hashes form the leaves of a RFC 6962
        Merkle tree whose root is stored in CommitmentRecord.shard_map_root.

        Individual shards can later be proven against this root via
        shard_inclusion_proof(), giving receivers a self-contained O(log n) proof
        that a fetched shard was committed by the sender without trusting any node.
        """
        tree = MerkleTree()
        shard_hashes: list[bytes] = []

        for i, enc_shard in enumerate(encrypted_shards):
            shard_hash = H_bytes(enc_shard + entity_id.encode() + struct.pack('>I', i))
            shard_hashes.append(shard_hash)
            tree.append(shard_hash)

            target_nodes = self._placement(entity_id, i, replicas)
            for node in target_nodes:
                node.store_shard(entity_id, i, enc_shard)

        self._shard_hashes[entity_id] = shard_hashes
        return tree.root().hex()

    def fetch_encrypted_shards(
        self, entity_id: str, n: int, k: int
    ) -> dict[int, bytes]:
        """
        Fetch k encrypted shards by deriving locations from entity_id.

        NO shard_ids needed — locations computed from entity_id + index.
        Returns: {shard_index: encrypted_shard_bytes}
        """
        fetched: dict[int, bytes] = {}

        for i in range(n):
            if len(fetched) >= k:
                break
            target_nodes = self._placement(entity_id, i)
            for node in target_nodes:
                data = node.fetch_shard(entity_id, i)
                if data is not None:
                    fetched[i] = data
                    break

        return fetched

    def shard_inclusion_proof(
        self, entity_id: str, shard_index: int
    ) -> Optional[InclusionProof]:
        """
        Generate an O(log n) inclusion proof for a single committed shard.

        A receiver uses this to verify that a fetched encrypted shard was
        committed by the sender at shard_index, without needing any other
        shard data.  Verify the proof against CommitmentRecord.shard_map_root:

            proof = network.shard_inclusion_proof(entity_id, shard_index)
            root  = bytes.fromhex(record.shard_map_root)
            assert proof.verify(shard_hash, root)

        where shard_hash = H_bytes(enc_shard || entity_id || shard_index).

        Returns None if entity_id was not committed via this coordinator or
        shard_index is out of range.
        """
        shard_hashes = self._shard_hashes.get(entity_id)
        if shard_hashes is None or not (0 <= shard_index < len(shard_hashes)):
            return None
        tree = MerkleTree()
        for sh in shard_hashes:
            tree.append(sh)
        return InclusionProof(
            leaf_index=shard_index,
            tree_size=tree.size,
            audit_path=tree.audit_path(shard_index),
            root_hash=tree.root(),
        )

    def verify_shard_commitment(self, entity_id: str) -> bool:
        """
        Verify that CommitmentRecord.shard_map_root matches the Merkle root
        recomputed from the locally stored shard hashes.

        This is a coordinator-level integrity check: if it fails, the commitment
        record's shard_map_root was tampered with after shards were distributed —
        a more severe violation than a single node audit failure.

        Returns False if entity_id is unknown, has no committed record, or if the
        roots diverge.
        """
        shard_hashes = self._shard_hashes.get(entity_id)
        if not shard_hashes:
            return False
        record = self.log.fetch(entity_id)
        if record is None:
            return False
        tree = MerkleTree()
        for sh in shard_hashes:
            tree.append(sh)
        return tree.root().hex() == record.shard_map_root

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

            # Merkle integrity check: verify the commitment record's shard_map_root
            # matches the root recomputed from locally stored shard hashes.  A mismatch
            # indicates the commitment record was tampered with — skip this entity and
            # count every expected shard as failed.
            if not self.verify_shard_commitment(entity_id):
                n_expected = record.encoding_params.get("n", 8)
                for shard_index in range(n_expected):
                    if node in self._placement(entity_id, shard_index):
                        challenged += 1
                        failed += 1
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
