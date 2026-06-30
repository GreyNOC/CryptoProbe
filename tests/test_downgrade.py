"""Downgrade-resistance verdict logic + hybrid correctness. No network."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoprobe import downgrade
from cryptoprobe.rawprobe import RawOutcome
from cryptoprobe.model import (
    ProbeResult, GroupObservation, HandshakeRecord, DowngradeVerdict,
    HybridVerdict,
)


def _clean():
    return RawOutcome(offered_groups=())


def test_classical_only_is_critical():
    v, strippable, _ = downgrade._derive(
        supports_pqc=False, prefers_pqc=False, classical_accepted=True,
        raw_pqc=_clean(), raw_cl=_clean())
    assert v is DowngradeVerdict.CLASSICAL_ONLY
    assert strippable is True
    assert v.severity.value == "CRITICAL"


def test_supports_but_not_prefers_is_vulnerable():
    v, strippable, _ = downgrade._derive(
        supports_pqc=True, prefers_pqc=False, classical_accepted=True,
        raw_pqc=_clean(), raw_cl=_clean())
    assert v is DowngradeVerdict.VULNERABLE
    assert strippable is True
    assert v.severity.value == "HIGH"


def test_prefers_pqc_but_classical_accepted_is_strippable():
    v, strippable, _ = downgrade._derive(
        supports_pqc=True, prefers_pqc=True, classical_accepted=True,
        raw_pqc=_clean(), raw_cl=_clean())
    assert v is DowngradeVerdict.PREFERS_PQC
    assert strippable is True
    assert v.severity.value == "MEDIUM"


def test_refuses_classical_is_resistant():
    v, strippable, _ = downgrade._derive(
        supports_pqc=True, prefers_pqc=True, classical_accepted=False,
        raw_pqc=_clean(), raw_cl=_clean())
    assert v is DowngradeVerdict.RESISTANT
    assert strippable is False
    assert v.severity.value == "INFO"


def test_transport_errors_are_unknown_not_guessed():
    bad = RawOutcome(offered_groups=(), error="ConnectionRefusedError")
    v, strippable, _ = downgrade._derive(
        supports_pqc=False, prefers_pqc=False, classical_accepted=False,
        raw_pqc=bad, raw_cl=bad)
    assert v is DowngradeVerdict.UNKNOWN
    assert strippable is None


def _result_with_group(group_name, completed_group=None):
    r = ProbeResult(host="h", port=443, is_tls13=True)
    r.group = GroupObservation(negotiated_group=group_name)
    if completed_group:
        r.completed_handshake = HandshakeRecord(
            method="openssl-s_client", completed=True,
            negotiated_group=completed_group)
    return r


def test_hybrid_correct_requires_completed_exchange():
    r = _result_with_group("X25519MLKEM768", completed_group="X25519MLKEM768")
    hc = downgrade._hybrid_check(r)
    assert hc.verdict is HybridVerdict.CORRECT
    assert hc.classical_present and hc.mlkem_present
    assert hc.expected_share_len == 1120


def test_hybrid_unknown_when_not_completed():
    r = _result_with_group("X25519MLKEM768")  # selected but not completed
    hc = downgrade._hybrid_check(r)
    assert hc.verdict is HybridVerdict.UNKNOWN  # never inferred from the label


def test_classical_group_is_not_hybrid():
    r = _result_with_group("x25519")
    hc = downgrade._hybrid_check(r)
    assert hc.verdict is HybridVerdict.NOT_HYBRID


def test_not_tls13_yields_unknown_downgrade():
    r = ProbeResult(host="h", port=443, is_tls13=False)
    downgrade.assess(r, timeout=1, limiter=None)
    assert r.downgrade.verdict is DowngradeVerdict.UNKNOWN
    assert r.hybrid.verdict is HybridVerdict.UNKNOWN
