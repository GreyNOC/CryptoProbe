"""
GreyNOC CryptoProbe — scan engine.

Ties the probe pipeline together for the ``scan`` command: per-target
authorization, rate limiting, validation, (downgrade + hybrid + conformance in
later phases), then deterministic rendering of the artifacts (JSON / human /
SARIF / CBOM / run manifest).

This module grows phase by phase; each addition is additive so the CLI surface
stays stable.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from . import log
from . import authz as authz_mod
from .targets import Target
from . import tlsverify, handshake
from ._version import __version__


class RateLimiter:
    """Minimum-interval limiter so a run does not hammer a target. Rate-limited
    by default (a GreyNOC operating standard)."""

    def __init__(self, per_sec: float | None):
        self.min_interval = (1.0 / per_sec) if per_sec and per_sec > 0 else 0.0
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        now = time.monotonic()
        delta = self.min_interval - (now - self._last)
        if delta > 0:
            time.sleep(delta)
        self._last = time.monotonic()


def run_scan(args, auth, targets: list[Target]) -> int:
    from .cli import EXIT_OK

    effective_rate = (auth.scope.rate_limit if auth.scope and auth.scope.rate_limit
                      else args.rate_limit)
    limiter = RateLimiter(effective_rate)
    run_dt = datetime.now(timezone.utc)
    cap = handshake.capability()
    if not cap.available:
        log.warn(f"openssl unavailable ({cap.detail}); completed-handshake "
                 f"evidence will be UNKNOWN")
    elif not cap.supports_mlkem:
        log.warn(f"openssl {cap.version} lacks ML-KEM groups; completed PQC "
                 f"handshakes will be UNKNOWN")

    results = []
    for t in targets:
        allowed, reason = authz_mod.authorize_target(auth, t.host, t.port)
        if not allowed:
            log.warn(f"skipping {t}: {reason}")
            continue
        log.info(f"probing {t}")
        # The limiter is threaded through validate() + downgrade.assess() so every
        # handshake in the run is rate-spaced, not just the first per target.
        result = tlsverify.validate(t.host, t.port, timeout=args.timeout,
                                    do_completed=not args.no_completed_handshake,
                                    limiter=limiter)
        _enrich(args, result, limiter, run_dt)
        results.append(result)
        _log_one(result)

    if not results and not args.cbom_in:
        log.warn("no targets probed")
        return EXIT_OK

    run_meta = _run_meta(args, auth, cap, effective_rate, run_dt)
    doc = build_document(results, run_meta)

    _emit(args, doc, results)

    code = _gate(results, args.fail_on)
    if code:
        log.gate(f"verdicts at or above '{args.fail_on}' severity present")
    return code if code else EXIT_OK


def _enrich(args, result, limiter, run_dt) -> None:
    """Downgrade/hybrid + conformance enrichment for one target."""
    if result.error:
        return
    if not args.no_downgrade:
        from . import downgrade
        downgrade.assess(result, timeout=args.timeout, limiter=limiter)
    from . import conformance
    conformance.evaluate(result, profile=args.profile, run_date=run_dt.date(),
                         fips_module=getattr(args, "fips_module", None))


def _run_meta(args, auth, cap, effective_rate, run_dt) -> dict:
    meta = {
        "tool": {"name": "GreyNOC CryptoProbe", "vendor": "GreyNOC",
                 "version": __version__},
        "timestamp": run_dt.isoformat(),
        "authorization": auth.to_dict(),
        "profile": args.profile,
        "rate_limit_per_sec": effective_rate,
        "openssl": cap.to_dict(),
        "discipline": "authorized-testing-only;reproducible;no-fabrication",
    }
    try:
        from . import conformance
        meta["policy"] = {
            "fips_snapshot_date": conformance.fips_snapshot_date(),
            "pack_hashes": conformance.pack_hashes(),
        }
    except ImportError:
        pass
    return meta


def build_document(results, run_meta) -> dict:
    """Deterministic top-level result document (sorted by target)."""
    ordered = sorted(results, key=lambda r: (r.host, r.port))
    return {
        "run": run_meta,
        "summary": _summary(ordered),
        "targets": [r.to_dict() for r in ordered],
    }


def _summary(results) -> dict:
    from .model import DowngradeVerdict
    n = len(results)
    tls13 = sum(1 for r in results if r.is_tls13)
    hybrid = sum(1 for r in results
                 if r.group and r.group.group_kind.value == "hybrid-pqc")
    classical = sum(1 for r in results
                    if r.group and r.group.group_kind.value == "classical")
    vulnerable = sum(
        1 for r in results if r.downgrade
        and r.downgrade.verdict in (DowngradeVerdict.VULNERABLE,
                                    DowngradeVerdict.CLASSICAL_ONLY))
    fails = sum(1 for r in results for c in r.conformance
                if c.verdict.value == "FAIL")
    return {
        "targets": n,
        "tls13": tls13,
        "negotiated_hybrid_pqc": hybrid,
        "negotiated_classical": classical,
        "downgrade_vulnerable": vulnerable,
        "conformance_failures": fails,
    }


def _emit(args, doc, results) -> None:
    fmt = args.format
    out_text = None
    if fmt == "json":
        out_text = json.dumps(doc, indent=2, sort_keys=False)
    elif fmt == "sarif":
        try:
            from . import sarif
            out_text = json.dumps(sarif.build_sarif(results, doc["run"]), indent=2)
        except ImportError:
            out_text = json.dumps(doc, indent=2)
    else:  # human
        try:
            from . import report
            out_text = report.render(results, doc["run"])
        except ImportError:
            out_text = _human_fallback(doc)
    if out_text is not None:
        print(out_text)

    if args.json_out:
        log.write_text(args.json_out, json.dumps(doc, indent=2))
        log.ok(f"JSON written: {args.json_out}")
    if getattr(args, "report", None):
        try:
            from . import report
            log.write_text(args.report, report.render(results, doc["run"]))
            log.ok(f"Report written: {args.report}")
        except ImportError:
            pass
    if getattr(args, "sarif", None):
        try:
            from . import sarif
            log.write_text(args.sarif, json.dumps(sarif.build_sarif(results, doc["run"]), indent=2))
            log.ok(f"SARIF written: {args.sarif}")
        except ImportError:
            pass
    if getattr(args, "cbom_out", None):
        try:
            from . import cbom
            doc_cbom = cbom.build(results, doc["run"], cbom_in=args.cbom_in)
            log.write_text(args.cbom_out, json.dumps(doc_cbom, indent=2))
            log.ok(f"CBOM written: {args.cbom_out} ({len(doc_cbom['components'])} components)")
        except ImportError:
            log.warn("CBOM emitter not available yet")
    if getattr(args, "run_out", None):
        from . import manifest
        man = manifest.build(doc, results, args)
        log.write_text(args.run_out, json.dumps(man, indent=2))
        log.ok(f"Run manifest written: {args.run_out}")


def _human_fallback(doc: dict) -> str:
    lines = [f"=== GreyNOC CryptoProbe {doc['run']['tool']['version']} ==="]
    s = doc["summary"]
    lines.append(f"targets={s['targets']} tls1.3={s['tls13']} "
                 f"hybrid-pqc={s['negotiated_hybrid_pqc']} "
                 f"classical={s['negotiated_classical']}")
    for t in doc["targets"]:
        g = t["group"]
        lines.append(f"  {t['target']}: {t['negotiated_version']} / "
                     f"{g['negotiated_group']} ({g['group_kind']})")
    return "\n".join(lines)


def _log_one(result) -> None:
    g = result.group
    if result.error:
        log.warn(f"  {result.target}: {result.error}")
        return
    ch = result.completed_handshake
    completed = ch.completed if ch else None
    log.info(f"  {result.target}: {result.negotiated_version} / "
             f"{g.negotiated_group} ({g.group_kind.value}) "
             f"completed={completed}")


def _gate(results, fail_on: str) -> int:
    from .primitives import Severity
    if fail_on == "none":
        return 0
    threshold = Severity[fail_on.upper()].rank
    worst = -1
    for r in results:
        if r.downgrade:
            worst = max(worst, r.downgrade.verdict.severity.rank)
        if r.hybrid:
            worst = max(worst, r.hybrid.verdict.severity.rank)
        for c in r.conformance:
            if c.verdict.value == "FAIL":
                worst = max(worst, c.severity.rank)
    return 2 if worst >= threshold else 0
