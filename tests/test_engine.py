"""Engine gate + multi-target document/CBOM. No network."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoprobe import engine, cbom, conformance
from cryptoprobe.model import (
    ProbeResult, GroupObservation, DowngradeResult, DowngradeVerdict,
    ConformanceFinding, ConformanceVerdict,
)
from cryptoprobe.primitives import Severity, GroupKind


def _res(host, dverdict=None, conf=None, kind=GroupKind.HYBRID_PQC,
         negotiated="X25519MLKEM768"):
    r = ProbeResult(host=host, port=443, reachable=True, is_tls13=True,
                    negotiated_version="TLSv1.3")
    r.group = GroupObservation(negotiated_group=negotiated, group_kind=kind)
    if dverdict is not None:
        r.downgrade = DowngradeResult(verdict=dverdict, strippable=True)
    if conf is not None:
        r.conformance = conf
    return r


def _conf(verdict, sev):
    return ConformanceFinding(pack="p", pack_title="t", profile="nss", rule_id="r",
                              requirement="x", verdict=verdict, severity=sev)


def test_gate_none_never_fails():
    assert engine._gate([_res("a", DowngradeVerdict.CLASSICAL_ONLY)], "none") == 0


def test_gate_prefers_pqc_is_medium():
    r = _res("a", DowngradeVerdict.PREFERS_PQC)
    assert engine._gate([r], "high") == 0
    assert engine._gate([r], "medium") == 2


def test_gate_vulnerable_is_high():
    assert engine._gate([_res("a", DowngradeVerdict.VULNERABLE)], "high") == 2


def test_gate_conformance_fail_gates():
    r = _res("a", conf=[_conf(ConformanceVerdict.FAIL, Severity.HIGH)])
    assert engine._gate([r], "high") == 2


def test_gate_warn_does_not_gate():
    # only FAIL conformance findings gate; WARN never does (nist-ir-8547 relies on this)
    r = _res("a", conf=[_conf(ConformanceVerdict.WARN, Severity.MEDIUM)])
    assert engine._gate([r], "medium") == 0


def _meta():
    return {"timestamp": "T", "tool": {"version": "0.1.0"}, "profile": "both",
            "policy": {"pack_hashes": conformance.pack_hashes()}}


def test_build_document_orders_and_summarizes():
    r1 = _res("aaa", kind=GroupKind.HYBRID_PQC, negotiated="X25519MLKEM768")
    r2 = _res("zzz", DowngradeVerdict.CLASSICAL_ONLY, kind=GroupKind.CLASSICAL,
              negotiated="x25519")
    doc = engine.build_document([r2, r1], _meta())  # passed out of order
    assert [t["host"] for t in doc["targets"]] == ["aaa", "zzz"]
    s = doc["summary"]
    assert s["targets"] == 2
    assert s["negotiated_hybrid_pqc"] == 1
    assert s["negotiated_classical"] == 1
    assert s["downgrade_vulnerable"] == 1  # CLASSICAL_ONLY counts


def test_cbom_multitarget_serial_and_metadata():
    r1, r2 = _res("aaa"), _res("zzz")
    a = cbom.build([r1, r2], _meta())
    b = cbom.build([r2, r1], _meta())  # order-independent
    assert a["serialNumber"] == b["serialNumber"]
    assert a["metadata"]["component"]["name"] == "2 targets"
    single = cbom.build([r1], _meta())
    assert single["serialNumber"] != a["serialNumber"]
