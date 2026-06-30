"""Golden-file determinism: same inputs + same packs -> byte-identical output,
modulo the explicit run timestamp. No network."""

import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoprobe import conformance, cbom, report, sarif, engine, manifest
from cryptoprobe.model import (
    ProbeResult, GroupObservation, CertInfo, HandshakeRecord, DowngradeResult,
    DowngradeProbe, DowngradeVerdict, HybridCheck, HybridVerdict,
)
from cryptoprobe.primitives import SigClass, GroupKind


def _fixed_result():
    r = ProbeResult(host="pq.cloudflareresearch.com", port=443, reachable=True,
                    is_tls13=True, negotiated_version="TLSv1.3", version_below_13=False)
    r.group = GroupObservation(negotiated_group="X25519MLKEM768",
                               negotiated_group_code=0x11EC,
                               group_kind=GroupKind.HYBRID_PQC,
                               iana_recommended=True, nist_category=3,
                               supports_hybrid_pqc=True,
                               accepted_groups=["X25519MLKEM768"])
    ch = HandshakeRecord(method="openssl-s_client", completed=True,
                         negotiated_group="X25519MLKEM768",
                         negotiated_cipher="TLS_AES_256_GCM_SHA384",
                         transcript=b"fixed-completed-transcript")
    ch.finalize()
    r.completed_handshake = ch
    raw = HandshakeRecord(method="raw-probe", offered_groups=["X25519MLKEM768"],
                          negotiated_group="X25519MLKEM768", is_hrr=True,
                          transcript=b"fixed-raw-transcript")
    raw.finalize()
    r.handshakes = [raw, ch]
    r.cert = CertInfo(subject="CN=x", issuer="CN=ca", sig_algo="ecdsa-with-SHA256",
                      sig_class=SigClass.CLASSICAL, sig_canonical="ECDSA",
                      key_algo="ECDSA", key_size=256, der_sha256="cafe")
    r.hybrid = HybridCheck(verdict=HybridVerdict.CORRECT, group="X25519MLKEM768",
                           classical_present=True, mlkem_present=True,
                           reason="completed real hybrid")
    r.downgrade = DowngradeResult(
        verdict=DowngradeVerdict.PREFERS_PQC, strippable=True,
        reason="prefers pqc but classical accepted",
        probes=[DowngradeProbe("classical-only", ["x25519"], "completed", "x25519", "")])
    conformance.evaluate(r, profile="both", run_date=date(2026, 6, 29))
    return r


def _meta(ts):
    return {"tool": {"name": "GreyNOC CryptoProbe", "version": "0.1.0"},
            "timestamp": ts, "profile": "both",
            "authorization": {"identifier": "OP-1", "source": "flag"},
            "openssl": {"available": True, "version": "OpenSSL 3.5.5"},
            "policy": {"pack_hashes": conformance.pack_hashes(),
                       "fips_snapshot_date": "2026-06-15"}}


def _blank_ts(s, ts):
    return s.replace(ts, "<TS>")


def test_cbom_byte_identical_modulo_timestamp():
    r = _fixed_result()
    a = json.dumps(cbom.build([r], _meta("2026-01-01T00:00:00Z")), indent=2)
    b = json.dumps(cbom.build([r], _meta("2026-12-31T23:59:59Z")), indent=2)
    assert _blank_ts(a, "2026-01-01T00:00:00Z") == _blank_ts(b, "2026-12-31T23:59:59Z")


def test_engine_document_identical_modulo_timestamp():
    r = _fixed_result()
    a = json.dumps(engine.build_document([r], _meta("T-AAA")), indent=2, sort_keys=True)
    b = json.dumps(engine.build_document([r], _meta("T-BBB")), indent=2, sort_keys=True)
    assert _blank_ts(a, "T-AAA") == _blank_ts(b, "T-BBB")


def test_report_identical_modulo_timestamp():
    r = _fixed_result()
    a = report.render([r], _meta("TS-AAA"))
    b = report.render([r], _meta("TS-BBB"))
    assert _blank_ts(a, "TS-AAA") == _blank_ts(b, "TS-BBB")


def test_sarif_fully_identical():
    r = _fixed_result()
    a = json.dumps(sarif.build_sarif([r], _meta("X")), indent=2, sort_keys=True)
    b = json.dumps(sarif.build_sarif([r], _meta("Y")), indent=2, sort_keys=True)
    assert a == b  # SARIF carries no run timestamp


def test_manifest_results_digest_is_timestamp_independent():
    r = _fixed_result()
    da = engine.build_document([r], _meta("T1"))
    db = engine.build_document([r], _meta("T2"))
    assert manifest.results_digest(da) == manifest.results_digest(db)
