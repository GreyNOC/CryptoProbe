"""
GreyNOC CryptoProbe — downgrade-resistance + hybrid-correctness probing.

This is GreyNOC's offensive-security edge: can a network attacker strip the PQC
key shares from a ClientHello and force the server into classical key
establishment (the harvest-now-decrypt-later exposure)? We answer it from
observed handshakes only, with three controlled legs:

  pqc-only          offer only the ML-KEM hybrids        -> does it accept PQC?
  hybrid+classical  offer hybrids first, then classical  -> does it PREFER PQC?
  classical-only    offer only classical groups          -> will it drop to classical?

Every leg is a recorded artifact. We never go beyond handshake negotiation.

Verdict (no overclaiming — strippability is the question):
  RESISTANT       supports PQC, prefers PQC, and REFUSES classical-only
                  -> stripping PQC yields a handshake failure, not a fallback.
  PREFERS_PQC     supports + prefers PQC, but classical-only still completes
                  -> normal clients are protected, an active stripper can force
                     classical. Acceptable mid-transition; still strippable.
  VULNERABLE      supports PQC but does NOT prefer it (negotiates classical by
                  default) -> a silent fallback even without an attacker.
  CLASSICAL_ONLY  no PQC path at all -> quantum-vulnerable key establishment.
  UNKNOWN         could not determine (e.g. not TLS 1.3, or probes inconclusive).

Hybrid correctness: when a hybrid is negotiated, a *completed* hybrid handshake
(openssl) proves both the classical and ML-KEM halves were present and
well-formed. Without a completed exchange we report UNKNOWN — we do not infer
correctness from a group label alone.
"""

from __future__ import annotations

from . import log
from . import rawprobe, handshake
from .primitives import NamedGroup
from .model import (
    DowngradeResult, DowngradeProbe, DowngradeVerdict, HybridCheck, HybridVerdict,
)


def _raw_completed_hybrid(raw: rawprobe.RawOutcome) -> NamedGroup | None:
    if raw.error or raw.alert or raw.selected_group is None:
        return None
    g = NamedGroup.from_code(raw.selected_group)
    return g if (g and g.is_hybrid_pqc) else None


def _raw_classical_ok(raw: rawprobe.RawOutcome) -> bool:
    if raw.error or raw.alert or not raw.is_server_hello:
        return False
    g = NamedGroup.from_code(raw.selected_group) if raw.selected_group else None
    return g is not None and g.is_classical


def assess(result, *, timeout: float = 8.0, limiter=None) -> None:
    """Populate result.downgrade and result.hybrid from controlled handshakes."""
    def wait():
        if limiter is not None:
            limiter.wait()

    if not result.is_tls13:
        result.downgrade = DowngradeResult(
            verdict=DowngradeVerdict.UNKNOWN,
            reason="PQC key-exchange groups are a TLS 1.3 feature; endpoint did "
                   "not negotiate TLS 1.3")
        result.hybrid = HybridCheck(
            verdict=HybridVerdict.UNKNOWN, reason="not TLS 1.3")
        return

    host, port = result.host, result.port
    cap = handshake.capability()
    probes: list[DowngradeProbe] = []

    # --- leg 1: PQC / hybrid only -------------------------------------------
    wait()
    raw_pqc = rawprobe.probe_offer(host, port, rawprobe.HYBRID_GROUPS, timeout=timeout)
    result.handshakes.append(_mk_record("downgrade:pqc-only", raw_pqc))
    pqc_group = _raw_completed_hybrid(raw_pqc)
    oss_pqc_completed = None
    if cap.available:
        wait()
        oss_pqc = handshake.complete_handshake(
            host, port, offered_groups=list(rawprobe.HYBRID_GROUPS), timeout=max(timeout, 10.0))
        result.handshakes.append(oss_pqc)
        oss_pqc_completed = bool(oss_pqc.completed and oss_pqc.negotiated_group
                                 and _is_hybrid_name(oss_pqc.negotiated_group))
    supports_pqc = bool(pqc_group) or bool(oss_pqc_completed)
    probes.append(DowngradeProbe(
        name="pqc-only",
        offered_groups=[g.name for g in rawprobe.HYBRID_GROUPS],
        outcome=("completed" if oss_pqc_completed else
                 "selected" if pqc_group else
                 ("refused" if (raw_pqc.alert or raw_pqc.error) else "unknown")),
        negotiated_group=(pqc_group.name if pqc_group else
                          (oss_pqc.negotiated_group if oss_pqc_completed else None)),
        detail="server accepts a PQC/hybrid key exchange" if supports_pqc
               else "server did not accept any offered ML-KEM hybrid"))

    # --- leg 2: hybrid + classical (default offer; reuse base result) -------
    neg = result.group.negotiated_group
    prefers_pqc = bool(neg and _is_hybrid_name(neg))
    probes.append(DowngradeProbe(
        name="hybrid+classical",
        offered_groups=[g.name for g in rawprobe.DEFAULT_OFFER],
        outcome=("prefers-pqc" if prefers_pqc else "fell-back-to-classical"),
        negotiated_group=neg,
        detail="hybrids offered first; this is what the server selected"))

    # --- leg 3: classical only ----------------------------------------------
    wait()
    raw_cl = rawprobe.probe_offer(host, port, rawprobe.CLASSICAL_GROUPS, timeout=timeout)
    result.handshakes.append(_mk_record("downgrade:classical-only", raw_cl))
    classical_ok = _raw_classical_ok(raw_cl)
    oss_cl_completed = None
    if cap.available:
        wait()
        oss_cl = handshake.complete_handshake(
            host, port, offered_groups=list(rawprobe.CLASSICAL_GROUPS), timeout=max(timeout, 10.0))
        result.handshakes.append(oss_cl)
        oss_cl_completed = bool(oss_cl.completed)
    classical_accepted = bool(classical_ok) or bool(oss_cl_completed)
    probes.append(DowngradeProbe(
        name="classical-only",
        offered_groups=[g.name for g in rawprobe.CLASSICAL_GROUPS],
        outcome=("completed" if classical_accepted else
                 ("refused" if (raw_cl.alert or raw_cl.error) else "unknown")),
        negotiated_group=(raw_cl.selected_group_name if classical_ok else
                          (oss_cl.negotiated_group if oss_cl_completed else None)),
        detail=("server WILL complete a classical-only handshake — strippable"
                if classical_accepted else
                "server refuses a classical-only handshake")))

    verdict, strippable, reason = _derive(supports_pqc, prefers_pqc,
                                          classical_accepted, raw_pqc, raw_cl)
    result.downgrade = DowngradeResult(verdict=verdict, strippable=strippable,
                                       probes=probes, reason=reason)
    result.hybrid = _hybrid_check(result)
    log.debug(f"  {result.target}: downgrade={verdict.value} strippable={strippable} "
              f"hybrid={result.hybrid.verdict.value}")


def _derive(supports_pqc, prefers_pqc, classical_accepted, raw_pqc, raw_cl):
    # Could not get a clean read on either PQC support or classical acceptance.
    inconclusive = ((raw_pqc.error and not supports_pqc)
                    and (raw_cl.error and not classical_accepted))
    if inconclusive:
        return (DowngradeVerdict.UNKNOWN, None,
                "handshake probes were inconclusive (transport errors)")
    if not supports_pqc:
        if classical_accepted:
            return (DowngradeVerdict.CLASSICAL_ONLY, True,
                    "no PQC/hybrid key-exchange path; key establishment is "
                    "classical and quantum-vulnerable (HNDL-exposed)")
        return (DowngradeVerdict.UNKNOWN, None,
                "neither a PQC nor a classical handshake completed cleanly")
    # supports PQC
    if not prefers_pqc:
        return (DowngradeVerdict.VULNERABLE, True,
                "server supports PQC but negotiates classical by default — a "
                "silent fallback to classical key establishment")
    if classical_accepted:
        return (DowngradeVerdict.PREFERS_PQC, True,
                "server prefers PQC with normal clients but will still complete "
                "a classical-only handshake — an on-path attacker can strip the "
                "PQC groups and force classical key establishment")
    return (DowngradeVerdict.RESISTANT, False,
            "server prefers PQC and refuses a classical-only handshake — "
            "stripping the PQC groups yields a handshake failure, not a fallback")


def _hybrid_check(result) -> HybridCheck:
    neg = result.group.negotiated_group
    ng = _named(neg)
    if ng is None:
        return HybridCheck(verdict=HybridVerdict.UNKNOWN, group=neg,
                           reason="negotiated group not recognized")
    if not ng.is_hybrid_pqc:
        return HybridCheck(verdict=HybridVerdict.NOT_HYBRID, group=ng.name,
                           reason="negotiated group is not an ML-KEM hybrid")
    expected = ng.expected_server_share_len
    ch = result.completed_handshake
    if ch and ch.completed and _is_hybrid_name(ch.negotiated_group or ""):
        return HybridCheck(
            verdict=HybridVerdict.CORRECT, group=ng.name,
            classical_present=True, mlkem_present=True,
            expected_share_len=expected,
            reason="completed a real hybrid key exchange (openssl): both the "
                   "ECDHE and ML-KEM halves were present and well-formed")
    # We saw the hybrid selected (e.g. via HelloRetryRequest) but did not
    # complete the exchange, so we cannot inspect the share. Honest UNKNOWN.
    return HybridCheck(
        verdict=HybridVerdict.UNKNOWN, group=ng.name,
        expected_share_len=expected,
        reason="server selected the hybrid group but the key exchange was not "
               "completed (openssl unavailable); share well-formedness "
               "unverified — not inferred from the group label")


def _mk_record(label: str, raw: rawprobe.RawOutcome):
    from .model import HandshakeRecord
    rec = HandshakeRecord(
        method="raw-probe",
        offered_groups=[g.name for g in raw.offered_groups],
        negotiated_version=None,
        negotiated_group=raw.selected_group_name,
        negotiated_group_code=raw.selected_group,
        server_share_len=raw.server_share_len,
        is_hrr=raw.is_hrr,
        alert=(f"level={raw.alert[0]} desc={raw.alert[1]}" if raw.alert else None),
        error=raw.error,
        transcript=raw.transcript,
    )
    rec.finalize()
    rec.summary = f"[{label}] " + (raw.selected_group_name or raw.error or "no response")
    return rec


def _named(name: str | None) -> NamedGroup | None:
    if not name:
        return None
    low = name.lower()
    for g in NamedGroup:
        if g.name.lower() == low:
            return g
    return None


def _is_hybrid_name(name: str) -> bool:
    g = _named(name)
    return g is not None and g.is_hybrid_pqc
