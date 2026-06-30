"""Declarative conformance engine — divergence, FIPS, tri-state. No network."""

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoprobe import conformance
from cryptoprobe.model import (
    ProbeResult, GroupObservation, CertInfo, HandshakeRecord, ConformanceVerdict,
)
from cryptoprobe.primitives import SigClass


def _result(group, sig_class, sig_canon, sig_algo, cipher="TLS_AES_256_GCM_SHA384"):
    r = ProbeResult(host="h", port=443, reachable=True, is_tls13=True,
                    negotiated_version="TLSv1.3", version_below_13=False)
    r.group = GroupObservation(negotiated_group=group)
    r.completed_handshake = HandshakeRecord(
        method="openssl-s_client", completed=True, negotiated_group=group,
        negotiated_cipher=cipher)
    r.cert = CertInfo(sig_algo=sig_algo, sig_class=sig_class,
                      sig_canonical=sig_canon, key_algo="ECDSA")
    return r


def _by_rule(findings):
    return {f.rule_id: f.verdict for f in findings}


def test_packs_load_and_provenance_matches():
    packs = conformance.load_packs()
    ids = {p["id"] for p in packs}
    assert {"cnsa-2.0", "omb-m-26-15", "fips-140-3", "nist-ir-8547"} <= ids
    # PROVENANCE.json matches the shipped pack bytes.
    prov = conformance.load_provenance()
    assert prov is not None
    assert prov["hashes"] == conformance.pack_hashes()


def test_mlkem768_nss_fails_civilian_passes():
    """ML-KEM-768 hybrid: CNSA requires 1024 (FAIL); civilian accepts it (PASS)."""
    r = _result("X25519MLKEM768", SigClass.CLASSICAL, "ECDSA", "ecdsa-with-SHA256")
    v = _by_rule(conformance.evaluate(r, profile="both", run_date=date(2026, 6, 29)))
    assert v["cnsa-kex-mlkem1024"] is ConformanceVerdict.FAIL
    assert v["omb-kex-mlkem"] is ConformanceVerdict.PASS


def test_mlkem1024_satisfies_cnsa_kex():
    r = _result("SecP384r1MLKEM1024", SigClass.CLASSICAL, "ECDSA", "ecdsa-with-SHA256")
    v = _by_rule(conformance.evaluate(r, profile="nss", run_date=date(2026, 6, 29)))
    assert v["cnsa-kex-mlkem1024"] is ConformanceVerdict.PASS


def test_slh_dsa_divergence():
    """The headline NSS-vs-civilian divergence: same SLH-DSA cert, opposite verdicts."""
    r = _result("SecP384r1MLKEM1024", SigClass.PQC, "SLH-DSA-SHA2-256s",
                "SLH-DSA-SHA2-256s")
    v = _by_rule(conformance.evaluate(r, profile="both", run_date=date(2026, 6, 29)))
    # NSS: SLH-DSA is not approved -> FAIL
    assert v["cnsa-no-slh-dsa"] is ConformanceVerdict.FAIL
    # Civilian: SLH-DSA permitted as hash-based fallback -> PASS
    assert v["omb-slh-dsa-permitted"] is ConformanceVerdict.PASS
    assert v["omb-sig-pqc"] is ConformanceVerdict.PASS


def test_classical_cert_runway_warns_not_fails():
    r = _result("X25519MLKEM768", SigClass.CLASSICAL, "ECDSA", "ecdsa-with-SHA256")
    v = _by_rule(conformance.evaluate(r, profile="civilian", run_date=date(2026, 6, 29)))
    # IR 8547 is a draft -> advisory WARN, not FAIL
    assert v["ir8547-classical-sig-runway"] is ConformanceVerdict.WARN


def test_aes256_sha384_pass_under_cnsa():
    r = _result("SecP384r1MLKEM1024", SigClass.CLASSICAL, "ECDSA", "ecdsa-with-SHA256")
    v = _by_rule(conformance.evaluate(r, profile="nss", run_date=date(2026, 6, 29)))
    assert v["cnsa-aes256"] is ConformanceVerdict.PASS
    assert v["cnsa-sha384"] is ConformanceVerdict.PASS


def test_aes128_fails_cnsa():
    r = _result("SecP384r1MLKEM1024", SigClass.CLASSICAL, "ECDSA",
                "ecdsa-with-SHA256", cipher="TLS_AES_128_GCM_SHA256")
    v = _by_rule(conformance.evaluate(r, profile="nss", run_date=date(2026, 6, 29)))
    assert v["cnsa-aes256"] is ConformanceVerdict.FAIL
    assert v["cnsa-sha384"] is ConformanceVerdict.FAIL


def test_chacha20_fails_cnsa_aes256():
    # finding #4: CNSA requires AES-256 specifically, not any 256-bit cipher.
    r = _result("SecP384r1MLKEM1024", SigClass.CLASSICAL, "ECDSA",
                "ecdsa-with-SHA256", cipher="TLS_CHACHA20_POLY1305_SHA256")
    v = _by_rule(conformance.evaluate(r, profile="nss", run_date=date(2026, 6, 29)))
    assert v["cnsa-aes256"] is ConformanceVerdict.FAIL


def test_unclassifiable_signature_is_not_fabricated_fail():
    # finding #7: an observed cert whose signature can't be classified must not
    # produce a "classical" FAIL — the sig rules become N/A (unobserved class).
    r = _result("X25519MLKEM768", SigClass.UNKNOWN, None, "weird-unknown-sig-oid")
    v = _by_rule(conformance.evaluate(r, profile="both", run_date=date(2026, 6, 29)))
    assert v["omb-sig-pqc"] is ConformanceVerdict.NOT_APPLICABLE
    assert v["cnsa-sig-mldsa87"] is ConformanceVerdict.NOT_APPLICABLE


def test_fips_module_date_logic():
    r = _result("X25519MLKEM768", SigClass.CLASSICAL, "ECDSA", "ecdsa-with-SHA256")

    def fips_verdict(module, run_date):
        fs = conformance.evaluate(r, profile="civilian", run_date=run_date,
                                  fips_module=module)
        return {f.rule_id: f for f in fs}["fips-140-3-module"].verdict

    # FIPS 140-2 module: WARN before the cutoff, FAIL on/after.
    assert fips_verdict("OpenSSL FIPS Provider 3.0", date(2026, 6, 29)) is ConformanceVerdict.WARN
    assert fips_verdict("OpenSSL FIPS Provider 3.0", date(2026, 10, 1)) is ConformanceVerdict.FAIL
    # FIPS 140-3 module: PASS.
    assert fips_verdict("wolfCrypt", date(2026, 10, 1)) is ConformanceVerdict.PASS
    # Unknown / unobserved module: UNKNOWN, never guessed.
    assert fips_verdict(None, date(2026, 10, 1)) is ConformanceVerdict.UNKNOWN
    assert fips_verdict("nonexistent-module", date(2026, 10, 1)) is ConformanceVerdict.UNKNOWN
    # Generic substring must NOT match a specific CMVP entry (finding #16).
    assert fips_verdict("openssl", date(2026, 10, 1)) is ConformanceVerdict.UNKNOWN
    assert fips_verdict("3.0", date(2026, 10, 1)) is ConformanceVerdict.UNKNOWN


def test_version_below_tls13_fails_eo_rule():
    # finding #11: a sub-TLS-1.3 endpoint FAILs the EO 14306 rule, kex -> N/A.
    r = ProbeResult(host="h", port=443, reachable=True, is_tls13=False,
                    negotiated_version="TLSv1.2", version_below_13=True)
    v = _by_rule(conformance.evaluate(r, profile="both", run_date=date(2026, 6, 29)))
    assert v["cnsa-tls13"] is ConformanceVerdict.FAIL
    assert v["omb-tls13"] is ConformanceVerdict.FAIL
    assert v["cnsa-kex-mlkem1024"] is ConformanceVerdict.NOT_APPLICABLE


def test_unobserved_reachability_is_unknown_not_fabricated():
    # reachable unobserved (None) -> the tls13 gate is UNKNOWN, never a FAIL.
    r = ProbeResult(host="h", port=443, reachable=None)
    v = _by_rule(conformance.evaluate(r, profile="both", run_date=date(2026, 6, 29)))
    assert v["cnsa-tls13"] is ConformanceVerdict.UNKNOWN
    assert v["omb-tls13"] is ConformanceVerdict.UNKNOWN


def test_unreachable_kex_facts_are_unknown_not_fail():
    """An unreachable/unknown KEX is UNKNOWN (unobserved), not a fabricated FAIL."""
    r = ProbeResult(host="h", port=443, reachable=True, is_tls13=True,
                    negotiated_version="TLSv1.3")
    r.group = GroupObservation(negotiated_group="0x9999")  # unknown group code
    v = _by_rule(conformance.evaluate(r, profile="nss", run_date=date(2026, 6, 29)))
    assert v["cnsa-kex-mlkem1024"] is ConformanceVerdict.UNKNOWN
