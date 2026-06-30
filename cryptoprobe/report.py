"""
GreyNOC CryptoProbe — human-readable report renderer.

Mirrors CryptoScan's ``report.render`` idioms: a deterministic, severity-ranked
Markdown report. Every line traces to an observed artifact; nothing is inferred.
``render(results, run_meta) -> str`` returns a newline-joined string.
"""

from __future__ import annotations

from .model import ConformanceVerdict

_VERDICT_ORDER = {
    ConformanceVerdict.FAIL: 0, ConformanceVerdict.WARN: 1,
    ConformanceVerdict.UNKNOWN: 2, ConformanceVerdict.PASS: 3,
    ConformanceVerdict.NOT_APPLICABLE: 4,
}
_MARK = {
    ConformanceVerdict.PASS: "PASS", ConformanceVerdict.FAIL: "FAIL",
    ConformanceVerdict.WARN: "WARN", ConformanceVerdict.UNKNOWN: "????",
    ConformanceVerdict.NOT_APPLICABLE: "n/a ",
}


def render(results, run_meta: dict) -> str:
    L: list[str] = []
    tool = run_meta.get("tool", {})
    L.append("# GreyNOC CryptoProbe — Active PQC Validation Report")
    L.append("")
    L.append(f"- tool: {tool.get('name')} {tool.get('version')}")
    L.append(f"- run: {run_meta.get('timestamp')}")
    L.append(f"- profile: {run_meta.get('profile')}")
    auth = run_meta.get("authorization", {})
    L.append(f"- authorization: {auth.get('identifier')} (source: {auth.get('source')})")
    ossl = run_meta.get("openssl", {})
    L.append(f"- openssl: {ossl.get('version') or 'unavailable'} "
             f"(completed-handshake evidence: {'yes' if ossl.get('available') else 'UNKNOWN'})")
    L.append("")

    ordered = sorted(results, key=lambda r: (r.host, r.port))
    _summary(L, ordered)

    for r in ordered:
        _target(L, r, run_meta.get("profile", "both"))

    L.append("")
    L.append("---")
    L.append("Authorized testing only. Every verdict above traces to a recorded "
             "handshake transcript, certificate, or ruleset match. Findings that "
             "could not be observed are reported UNKNOWN, not guessed.")
    return "\n".join(L)


def _summary(L: list[str], results) -> None:
    n = len(results)
    tls13 = sum(1 for r in results if r.is_tls13)
    hybrid = sum(1 for r in results if r.group.group_kind.value == "hybrid-pqc")
    classical = sum(1 for r in results if r.group.group_kind.value == "classical")
    strippable = sum(1 for r in results if r.downgrade and r.downgrade.strippable)
    fails = sum(1 for r in results for c in r.conformance
                if c.verdict is ConformanceVerdict.FAIL)
    L.append("## Summary")
    L.append("")
    L.append(f"- targets probed: {n}")
    L.append(f"- TLS 1.3: {tls13}/{n}")
    L.append(f"- negotiated PQC hybrid: {hybrid} · classical: {classical}")
    L.append(f"- downgrade-strippable: {strippable}")
    L.append(f"- conformance FAILs: {fails}")
    L.append("")


def _target(L: list[str], r, profile: str) -> None:
    L.append(f"## {r.target}")
    L.append("")
    if r.error:
        L.append(f"- unreachable: {r.error}")
        L.append("")
        return
    g = r.group
    tags = [g.group_kind.value]
    if g.iana_recommended:
        tags.append("IANA-recommended")
    if g.nist_category:
        tags.append(f"NIST cat {g.nist_category}")
    L.append(f"- negotiated: {r.negotiated_version} / {g.negotiated_group} "
             f"({', '.join(tags)})")
    ch = r.completed_handshake
    if ch:
        if ch.completed:
            L.append(f"- completed handshake: yes (openssl) "
                     f"cipher {ch.negotiated_cipher}")
        else:
            L.append(f"- completed handshake: no — {ch.error or 'UNKNOWN'}")
    if r.version_below_13:
        L.append("- ⚠ below TLS 1.3 — EO 14306 requires TLS 1.3 or a successor "
                 "(not later than 2030-01-02)")
    if r.cert:
        c = r.cert
        L.append(f"- certificate: {c.key_algo}"
                 f"{('/' + str(c.key_size)) if c.key_size else ''} · "
                 f"signature {c.sig_algo} ({c.sig_class.value})")
    if r.hybrid:
        L.append(f"- hybrid correctness: {r.hybrid.verdict.value} — {r.hybrid.reason}")
    if r.downgrade:
        d = r.downgrade
        strip = "" if d.strippable is None else (
            " · STRIPPABLE" if d.strippable else " · not strippable")
        L.append(f"- downgrade resistance: **{d.verdict.value}**{strip}")
        L.append(f"  - {d.reason}")
        for p in d.probes:
            L.append(f"  - leg `{p.name}` (offer {len(p.offered_groups)} groups): "
                     f"{p.outcome}" + (f" -> {p.negotiated_group}" if p.negotiated_group else ""))
    _conformance(L, r, profile)
    digs = r.transcript_digests()
    if digs:
        L.append(f"- transcripts recorded: {len(digs)} "
                 f"({', '.join(d['sha256'][:10] for d in digs[:4])}"
                 f"{'…' if len(digs) > 4 else ''})")
    L.append("")


def _conformance(L: list[str], r, profile: str) -> None:
    if not r.conformance:
        return
    findings = sorted(r.conformance,
                      key=lambda c: (_VERDICT_ORDER.get(c.verdict, 9),
                                     -c.severity.rank, c.pack, c.rule_id))
    L.append(f"- conformance (profile: {profile}):")
    for c in findings:
        deadline = f" [by {c.deadline}]" if c.deadline else ""
        L.append(f"  - [{_MARK[c.verdict]}] {c.severity.value:<8} "
                 f"{c.pack}/{c.rule_id}{deadline} — {c.requirement}")
        if c.verdict in (ConformanceVerdict.FAIL, ConformanceVerdict.WARN) and c.detail:
            L.append(f"        {' '.join(c.detail.split())}")
