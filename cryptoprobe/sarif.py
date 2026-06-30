"""
GreyNOC CryptoProbe — SARIF 2.1.0 renderer.

Mirrors CryptoScan's ``sarif.build_sarif`` (driver, rules, results, level +
security-severity mapping) so CryptoProbe findings drop into the same CI /
code-scanning tooling. Only actionable findings are emitted as results
(conformance FAIL/WARN, a non-resistant downgrade verdict, an incorrect hybrid);
PASS/N/A and INFO are not surfaced as alerts. Deterministic and sorted.
"""

from __future__ import annotations

from ._version import __version__
from .primitives import Severity
from .model import ConformanceVerdict, DowngradeVerdict, HybridVerdict

SARIF_VERSION = "2.1.0"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_NAME = "GreyNOC CryptoProbe"
INFO_URI = "https://github.com/GreyNOC"

_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error",
          Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
_SEC_SEV = {Severity.CRITICAL: "9.5", Severity.HIGH: "7.5", Severity.MEDIUM: "5.0",
            Severity.LOW: "3.0", Severity.INFO: "1.0"}


def _result(rule_id: str, severity: Severity, message: str, target: str,
            help_uri: str | None) -> tuple[dict, dict]:
    # A network endpoint is not a source file, so use a logicalLocation (valid
    # SARIF for results not tied to a file) rather than a physicalLocation with a
    # non-anchorable tls:// URI. security-severity lives on the RESULT (the
    # canonical, per-finding location) and NOT on the rule — a rule shared by
    # findings of different severity must not carry a single conflicting value.
    res = {
        "ruleId": rule_id,
        "level": _LEVEL[severity],
        "message": {"text": message},
        "locations": [{
            "logicalLocations": [{"fullyQualifiedName": target, "kind": "module"}]
        }],
        "properties": {"security-severity": _SEC_SEV[severity], "target": target},
    }
    rule = {"id": rule_id}
    if help_uri:
        rule["helpUri"] = help_uri
    return res, rule


def build_sarif(results, run_meta: dict) -> dict:
    rules: dict[str, dict] = {}
    sarif_results: list[dict] = []

    for r in sorted(results, key=lambda r: (r.host, r.port)):
        target = r.target
        # downgrade
        d = r.downgrade
        if d and d.verdict in (DowngradeVerdict.VULNERABLE,
                               DowngradeVerdict.CLASSICAL_ONLY,
                               DowngradeVerdict.PREFERS_PQC):
            res, rule = _result(
                f"greynoc/downgrade/{d.verdict.value}", d.verdict.severity,
                f"Downgrade resistance: {d.verdict.value}"
                + (" (strippable)" if d.strippable else "") + f" — {d.reason}",
                target, None)
            sarif_results.append(res)
            rules[rule["id"]] = rule
        # hybrid incorrect
        if r.hybrid and r.hybrid.verdict is HybridVerdict.INCORRECT:
            res, rule = _result(
                "greynoc/hybrid/incorrect", r.hybrid.verdict.severity,
                f"Hybrid key exchange malformed: {r.hybrid.reason}", target, None)
            sarif_results.append(res)
            rules[rule["id"]] = rule
        # conformance
        for c in sorted(r.conformance, key=lambda c: (c.pack, c.rule_id)):
            if c.verdict not in (ConformanceVerdict.FAIL, ConformanceVerdict.WARN):
                continue
            rid = f"greynoc/{c.pack}/{c.rule_id}"
            deadline = f" (by {c.deadline})" if c.deadline else ""
            res, rule = _result(
                rid, c.severity,
                f"[{c.verdict.value}] {c.mandate}: {c.requirement}{deadline} — "
                f"{' '.join(c.detail.split())}",
                target, c.citation)
            res["properties"]["mandate"] = c.mandate
            if c.deadline:
                res["properties"]["deadline"] = c.deadline
            sarif_results.append(res)
            rules[rid] = rule

    sarif_results.sort(key=lambda r: (r["properties"]["target"], r["ruleId"]))
    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "version": __version__,
                "informationUri": INFO_URI,
                "rules": [rules[k] for k in sorted(rules)],
            }},
            "results": sarif_results,
            "properties": {
                "targets": sorted(r.target for r in results),
                "discipline": "authorized-testing-only;reproducible;no-fabrication",
            },
        }],
    }
