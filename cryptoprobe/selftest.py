"""
GreyNOC CryptoProbe — selftest.

Validates the tool against known-good public PQC endpoints and runs offline
self-checks. The online checks use endpoints designated by their operators for
exactly this purpose (Cloudflare's PQC research endpoint, Google); ``--offline``
skips all network and runs only the offline checks.

Definition-of-done coverage: completes real PQC/hybrid handshakes against live
known-good endpoints and classifies them correctly; proves the classical-only
endpoint is classified VULNERABLE/CLASSICAL_ONLY (offline, deterministically);
proves the conformance NSS-vs-civilian divergence, pack provenance, and a
verifying signature.
"""

from __future__ import annotations

import tempfile
from datetime import date
from pathlib import Path

from . import log
from . import conformance, attest, handshake, tlsverify
from . import downgrade as downgrade_mod
from .primitives import NamedGroup, SigClass
from .model import (
    ProbeResult, GroupObservation, CertInfo, HandshakeRecord, DowngradeVerdict,
    ConformanceVerdict,
)
from .rawprobe import RawOutcome

KNOWN_GOOD = ["pq.cloudflareresearch.com:443", "www.google.com:443"]


def _check(name, fn):
    try:
        ok, detail = fn()
    except Exception as exc:  # noqa: BLE001
        return (name, False, f"{type(exc).__name__}: {exc}")
    return (name, ok, detail)


# --- offline checks --------------------------------------------------------

def _chk_pack_provenance():
    prov = conformance.load_provenance()
    if prov is None:
        return False, "PROVENANCE.json missing"
    ok = prov["hashes"] == conformance.pack_hashes()
    return ok, "pack hashes match PROVENANCE.json" if ok else "pack hash mismatch"


def _chk_group_classification():
    g = NamedGroup.X25519MLKEM768
    ok = (int(g) == 0x11EC and g.is_hybrid_pqc and g.iana_recommended
          and NamedGroup.SecP384r1MLKEM1024.nist_category == 5
          and NamedGroup.x25519.is_classical)
    return ok, "X25519MLKEM768=0x11EC hybrid; SecP384r1MLKEM1024 cat 5"


def _chk_classical_is_vulnerable():
    # A server with no PQC path that still completes classical -> CLASSICAL_ONLY.
    v, strippable, _ = downgrade_mod._derive(
        supports_pqc=False, prefers_pqc=False, classical_accepted=True,
        raw_pqc=RawOutcome(offered_groups=()), raw_cl=RawOutcome(offered_groups=()))
    ok = v is DowngradeVerdict.CLASSICAL_ONLY and v.severity.value == "CRITICAL"
    return ok, "classical-only key establishment -> CLASSICAL_ONLY (CRITICAL)"


def _chk_conformance_divergence():
    r = ProbeResult(host="h", port=443, reachable=True, is_tls13=True,
                    negotiated_version="TLSv1.3")
    r.group = GroupObservation(negotiated_group="X25519MLKEM768")
    r.completed_handshake = HandshakeRecord(method="x", completed=True,
                                            negotiated_cipher="TLS_AES_256_GCM_SHA384")
    r.cert = CertInfo(sig_algo="ecdsa-with-SHA256", sig_class=SigClass.CLASSICAL,
                      sig_canonical="ECDSA")
    v = {f.rule_id: f.verdict for f in
         conformance.evaluate(r, profile="both", run_date=date(2026, 6, 29))}
    ok = (v["cnsa-kex-mlkem1024"] is ConformanceVerdict.FAIL
          and v["omb-kex-mlkem"] is ConformanceVerdict.PASS)
    return ok, "ML-KEM-768: CNSA FAIL (needs 1024) vs civilian PASS"


def _chk_attestation_ed25519():
    with tempfile.TemporaryDirectory() as d:
        key = str(Path(d) / "ed.key")
        attest.generate_keypair("ed25519", key)
        man = {"run": {"timestamp": "x"}, "summary": {}, "targets": []}
        att = attest.sign(man, key, "ed25519")
        ok, _ = attest.verify(att)
        att["manifest"]["summary"]["tampered"] = True
        tampered_ok, _ = attest.verify(att)
    return (ok and not tampered_ok), "Ed25519 sign+verify ok; tamper rejected"


def _chk_attestation_ml_dsa():
    cap = handshake.capability()
    if not (cap.available and cap.supports_ml_dsa):
        return True, "skipped (openssl ML-DSA unavailable)"
    with tempfile.TemporaryDirectory() as d:
        key = str(Path(d) / "mldsa.key")
        attest.generate_keypair("ml-dsa-87", key)
        man = {"run": {"timestamp": "x"}, "summary": {}, "targets": []}
        att = attest.sign(man, key, "ml-dsa-87")
        ok, _ = attest.verify(att)
    return ok, "ML-DSA-87 sign+verify ok (dogfooded PQC)"


def _offline_checks():
    return [
        _check("pack provenance", _chk_pack_provenance),
        _check("group classification", _chk_group_classification),
        _check("classical endpoint -> vulnerable", _chk_classical_is_vulnerable),
        _check("NSS/civilian divergence", _chk_conformance_divergence),
        _check("attestation (Ed25519)", _chk_attestation_ed25519),
        _check("attestation (ML-DSA-87)", _chk_attestation_ml_dsa),
    ]


# --- online checks ---------------------------------------------------------

def _chk_endpoint(spec, timeout):
    host, _, port = spec.partition(":")
    r = tlsverify.validate(host, int(port or 443), timeout=timeout)
    if not r.reachable:
        return False, f"unreachable: {r.error}"
    if not r.is_tls13:
        return False, f"not TLS 1.3 ({r.negotiated_version})"
    if r.group.group_kind.value != "hybrid-pqc":
        return False, f"did not negotiate a PQC hybrid (got {r.group.negotiated_group})"
    ch = r.completed_handshake
    completed = " + completed handshake" if (ch and ch.completed) else ""
    return True, f"{r.group.negotiated_group} (hybrid-pqc){completed}"


def _online_checks(timeout):
    return [_check(f"live {spec}", lambda spec=spec: _chk_endpoint(spec, timeout))
            for spec in KNOWN_GOOD]


def run(args) -> int:
    log.force_utf8()
    print("GreyNOC CryptoProbe — selftest\n")
    cap = handshake.capability()
    print(f"openssl: {cap.version or 'unavailable'} "
          f"(ML-KEM groups: {cap.supports_mlkem}, ML-DSA: {cap.supports_ml_dsa})\n")

    checks = _offline_checks()
    if not getattr(args, "offline", False):
        checks += _online_checks(getattr(args, "timeout", 10.0))

    allok = True
    for name, ok, detail in checks:
        allok = allok and ok
        mark = "PASS" if ok else "FAIL"
        print(f"  [{mark}] {name}" + (f" — {detail}" if detail else ""))

    print()
    if allok:
        print("ALL CHECKS PASSED")
        return 0
    print("SELFTEST FAILURES PRESENT")
    return 1
