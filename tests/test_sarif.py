"""SARIF 2.1.0 output fidelity. No network."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoprobe import sarif
from cryptoprobe.model import (
    ProbeResult, GroupObservation, DowngradeResult, DowngradeVerdict,
    ConformanceFinding, ConformanceVerdict,
)
from cryptoprobe.primitives import Severity


def _result(host, dverdict):
    r = ProbeResult(host=host, port=443, reachable=True, is_tls13=True)
    r.group = GroupObservation(negotiated_group="x25519")
    r.downgrade = DowngradeResult(verdict=dverdict, strippable=True, reason="x")
    r.conformance = [ConformanceFinding(
        pack="cnsa-2.0", pack_title="t", profile="nss",
        rule_id="cnsa-kex-mlkem1024", requirement="ML-KEM-1024",
        verdict=ConformanceVerdict.FAIL, severity=Severity.CRITICAL,
        mandate="CNSA 2.0", deadline="2027-01-01")]
    return r


def test_security_severity_on_results_not_rules():
    # finding #10: a rule shared across severities must not carry one value.
    s = sarif.build_sarif([_result("a", DowngradeVerdict.VULNERABLE)], {})
    for rule in s["runs"][0]["tool"]["driver"]["rules"]:
        assert "security-severity" not in rule.get("properties", {})
    for res in s["runs"][0]["results"]:
        assert "security-severity" in res["properties"]
        assert "target" in res["properties"]


def test_same_ruleid_across_targets_is_single_rule():
    s = sarif.build_sarif(
        [_result("a", DowngradeVerdict.VULNERABLE),
         _result("b", DowngradeVerdict.CLASSICAL_ONLY)], {})
    ids = [r["id"] for r in s["runs"][0]["tool"]["driver"]["rules"]]
    assert len(ids) == len(set(ids))  # no duplicate / conflicting rule defs
    assert ids.count("greynoc/cnsa-2.0/cnsa-kex-mlkem1024") == 1


def test_uses_logical_location_not_tls_uri():
    # finding #21: a network endpoint is not a source file.
    s = sarif.build_sarif([_result("a", DowngradeVerdict.VULNERABLE)], {})
    loc = s["runs"][0]["results"][0]["locations"][0]
    assert "logicalLocations" in loc
    assert "physicalLocation" not in loc
    assert loc["logicalLocations"][0]["fullyQualifiedName"] == "a:443"


def test_deterministic_and_sorted():
    a = sarif.build_sarif([_result("z", DowngradeVerdict.VULNERABLE),
                           _result("a", DowngradeVerdict.VULNERABLE)], {})
    b = sarif.build_sarif([_result("a", DowngradeVerdict.VULNERABLE),
                           _result("z", DowngradeVerdict.VULNERABLE)], {})
    import json
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    targets = [r["properties"]["target"] for r in a["runs"][0]["results"]]
    assert targets == sorted(targets)
