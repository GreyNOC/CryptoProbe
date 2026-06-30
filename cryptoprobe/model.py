"""
GreyNOC CryptoProbe — result model.

The dataclasses here are the contract between the probe engine, the
downgrade/hybrid logic, the conformance engine, the CBOM enricher, the renderers
and the attestation manifest. Two principles govern every field:

  * No fabrication. Anything we could not observe is ``None`` / ``UNKNOWN`` with
    a reason — never a guess. Verdict enums all carry an explicit ``UNKNOWN``.
  * Reproducibility. ``to_dict()`` emits sorted, stable structures so two runs
    over identical inputs serialize byte-identically (modulo the run timestamp).

Raw handshake transcripts are kept as bytes on the records (``repr=False``, not
serialized) so the engine can SHA-256 them for provenance and optionally write
them out; the JSON/CBOM carry only the digest.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum

from .primitives import Severity, GroupKind, SigClass


class Evidence(str, Enum):
    """Whether a datum was actually observed."""
    OBSERVED = "observed"
    UNKNOWN = "unknown"
    ERROR = "error"


class HybridVerdict(str, Enum):
    CORRECT = "correct"          # both classical + ML-KEM shares present, well-formed
    INCORRECT = "incorrect"      # named a hybrid but the share is malformed/short
    NOT_HYBRID = "not-hybrid"    # negotiated group is not a hybrid
    UNKNOWN = "unknown"          # could not complete/inspect — not guessed

    @property
    def severity(self) -> Severity:
        return {
            HybridVerdict.CORRECT: Severity.INFO,
            HybridVerdict.INCORRECT: Severity.CRITICAL,
            HybridVerdict.NOT_HYBRID: Severity.INFO,
            HybridVerdict.UNKNOWN: Severity.LOW,
        }[self]


class DowngradeVerdict(str, Enum):
    RESISTANT = "resistant"      # server refuses to drop PQC -> no strip attack
    PREFERS_PQC = "prefers-pqc"  # prefers PQC in hybrid, but classical still accepted
    VULNERABLE = "vulnerable"    # silently falls back to classical -> strippable
    CLASSICAL_ONLY = "classical-only"  # no PQC path at all
    UNKNOWN = "unknown"

    @property
    def severity(self) -> Severity:
        return {
            DowngradeVerdict.RESISTANT: Severity.INFO,
            DowngradeVerdict.PREFERS_PQC: Severity.MEDIUM,
            DowngradeVerdict.VULNERABLE: Severity.HIGH,
            DowngradeVerdict.CLASSICAL_ONLY: Severity.CRITICAL,
            DowngradeVerdict.UNKNOWN: Severity.LOW,
        }[self]


class ConformanceVerdict(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    NOT_APPLICABLE = "N/A"
    UNKNOWN = "UNKNOWN"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class CertInfo:
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    sig_algo: str | None = None          # certificate signatureAlgorithm OID name
    sig_class: SigClass = SigClass.UNKNOWN
    sig_canonical: str | None = None
    key_algo: str | None = None
    key_size: int | None = None
    key_curve: str | None = None
    der_sha256: str | None = None
    self_signed: bool | None = None

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "signature_algorithm": self.sig_algo,
            "signature_class": self.sig_class.value,
            "signature_canonical": self.sig_canonical,
            "key_algorithm": self.key_algo,
            "key_size": self.key_size,
            "key_curve": self.key_curve,
            "der_sha256": self.der_sha256,
            "self_signed": self.self_signed,
        }


@dataclass
class HandshakeRecord:
    """One controlled handshake attempt — a recorded artifact every verdict
    traces back to. ``transcript`` bytes are not serialized; their digest is."""
    method: str                                  # "raw-probe" | "openssl-s_client"
    offered_groups: list[str] = field(default_factory=list)
    negotiated_version: str | None = None
    negotiated_group: str | None = None          # name or "0xXXXX" if unknown
    negotiated_group_code: int | None = None
    negotiated_cipher: str | None = None
    completed: bool | None = None                # full handshake finished (openssl)
    server_share_len: int | None = None
    is_hrr: bool | None = None
    alert: str | None = None
    error: str | None = None
    summary: str | None = None                   # short captured line
    transcript: bytes = field(default=b"", repr=False)
    transcript_sha256: str | None = None

    def finalize(self) -> "HandshakeRecord":
        if self.transcript and not self.transcript_sha256:
            self.transcript_sha256 = _sha256(self.transcript)
        return self

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "offered_groups": list(self.offered_groups),
            "negotiated_version": self.negotiated_version,
            "negotiated_group": self.negotiated_group,
            "negotiated_group_code": (f"0x{self.negotiated_group_code:04X}"
                                      if self.negotiated_group_code is not None
                                      else None),
            "negotiated_cipher": self.negotiated_cipher,
            "completed": self.completed,
            "server_share_len": self.server_share_len,
            "is_hello_retry_request": self.is_hrr,
            "alert": self.alert,
            "error": self.error,
            "summary": self.summary,
            "transcript_sha256": self.transcript_sha256,
        }


@dataclass
class GroupObservation:
    negotiated_group: str | None = None
    negotiated_group_code: int | None = None
    group_kind: GroupKind = GroupKind.UNKNOWN
    iana_recommended: bool | None = None
    nist_category: int | None = None
    supports_hybrid_pqc: bool | None = None
    accepted_groups: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "negotiated_group": self.negotiated_group,
            "negotiated_group_code": (f"0x{self.negotiated_group_code:04X}"
                                      if self.negotiated_group_code is not None
                                      else None),
            "group_kind": self.group_kind.value,
            "iana_recommended": self.iana_recommended,
            "nist_category": self.nist_category,
            "supports_hybrid_pqc": self.supports_hybrid_pqc,
            "accepted_groups": sorted(self.accepted_groups),
        }


@dataclass
class HybridCheck:
    verdict: HybridVerdict = HybridVerdict.UNKNOWN
    group: str | None = None
    classical_present: bool | None = None
    mlkem_present: bool | None = None
    server_share_len: int | None = None
    expected_share_len: int | None = None
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "group": self.group,
            "classical_present": self.classical_present,
            "mlkem_present": self.mlkem_present,
            "server_share_len": self.server_share_len,
            "expected_share_len": self.expected_share_len,
            "reason": self.reason,
        }


@dataclass
class DowngradeProbe:
    """One leg of the downgrade matrix: what we offered, what happened."""
    name: str                         # "pqc-only" | "hybrid+classical" | "classical-only"
    offered_groups: list[str]
    outcome: str                      # "completed" | "refused" | "fell-back" | "unknown"
    negotiated_group: str | None = None
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "offered_groups": list(self.offered_groups),
            "outcome": self.outcome,
            "negotiated_group": self.negotiated_group,
            "detail": self.detail,
        }


@dataclass
class DowngradeResult:
    verdict: DowngradeVerdict = DowngradeVerdict.UNKNOWN
    strippable: bool | None = None        # can a network attacker force classical?
    probes: list[DowngradeProbe] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "strippable": self.strippable,
            "reason": self.reason,
            "probes": [p.to_dict() for p in self.probes],
        }


@dataclass
class ConformanceFinding:
    pack: str                          # e.g. "cnsa-2.0"
    pack_title: str
    profile: str                       # "nss" | "civilian" | "general"
    rule_id: str
    requirement: str
    verdict: ConformanceVerdict
    severity: Severity
    observed: str = ""
    mandate: str = ""
    deadline: str | None = None
    citation: str | None = None
    detail: str = ""

    @property
    def sort_key(self) -> tuple:
        return (self.pack, self.rule_id)

    def to_dict(self) -> dict:
        return {
            "pack": self.pack,
            "pack_title": self.pack_title,
            "profile": self.profile,
            "rule_id": self.rule_id,
            "requirement": self.requirement,
            "verdict": self.verdict.value,
            "severity": self.severity.value,
            "observed": self.observed,
            "mandate": self.mandate,
            "deadline": self.deadline,
            "citation": self.citation,
            "detail": self.detail,
        }


@dataclass
class ProbeResult:
    host: str
    port: int
    reachable: bool = False
    error: str | None = None
    negotiated_version: str | None = None
    version_below_13: bool | None = None
    is_tls13: bool | None = None
    group: GroupObservation = field(default_factory=GroupObservation)
    cert: CertInfo | None = None
    completed_handshake: HandshakeRecord | None = None
    handshakes: list[HandshakeRecord] = field(default_factory=list)
    hybrid: HybridCheck | None = None
    downgrade: DowngradeResult | None = None
    conformance: list[ConformanceFinding] = field(default_factory=list)

    @property
    def target(self) -> str:
        if ":" in self.host and not self.host.startswith("["):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"

    def transcript_digests(self) -> list[dict]:
        """Sorted (method, sha256) for every handshake artifact — manifest input."""
        out = []
        for h in self.handshakes:
            if h.transcript_sha256:
                out.append({"method": h.method,
                            "offered_groups": list(h.offered_groups),
                            "sha256": h.transcript_sha256})
        return sorted(out, key=lambda d: (d["method"], d["sha256"]))

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "reachable": self.reachable,
            "error": self.error,
            "negotiated_version": self.negotiated_version,
            "version_below_tls13": self.version_below_13,
            "is_tls13": self.is_tls13,
            "group": self.group.to_dict(),
            "certificate": self.cert.to_dict() if self.cert else None,
            "completed_handshake": (self.completed_handshake.to_dict()
                                    if self.completed_handshake else None),
            "handshakes": [h.to_dict() for h in self.handshakes],
            "hybrid_correctness": self.hybrid.to_dict() if self.hybrid else None,
            "downgrade_resistance": self.downgrade.to_dict() if self.downgrade else None,
            "conformance": [c.to_dict()
                            for c in sorted(self.conformance, key=lambda c: c.sort_key)],
        }
