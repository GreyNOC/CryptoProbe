"""CBOM ingest / enrich / emit round-trip + determinism. No network.

Schema validation runs only when cyclonedx-python-lib is installed (the
[validation] extra); otherwise it is skipped, matching CryptoScan's CI.
"""

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from cryptoprobe import conformance, cbom
from cryptoprobe.model import (
    ProbeResult, GroupObservation, CertInfo, HandshakeRecord, DowngradeResult,
    DowngradeVerdict, HybridCheck, HybridVerdict,
)
from cryptoprobe.primitives import SigClass, GroupKind

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _result(host="pq.cloudflareresearch.com"):
    r = ProbeResult(host=host, port=443, reachable=True, is_tls13=True,
                    negotiated_version="TLSv1.3", version_below_13=False)
    r.group = GroupObservation(negotiated_group="X25519MLKEM768",
                               group_kind=GroupKind.HYBRID_PQC,
                               iana_recommended=True, nist_category=3)
    r.completed_handshake = HandshakeRecord(
        method="openssl-s_client", completed=True,
        negotiated_group="X25519MLKEM768",
        negotiated_cipher="TLS_AES_256_GCM_SHA384", transcript=b"fixed-transcript")
    r.completed_handshake.finalize()
    r.cert = CertInfo(sig_algo="ecdsa-with-SHA256", sig_class=SigClass.CLASSICAL,
                      sig_canonical="ECDSA", key_algo="ECDSA", key_size=256,
                      der_sha256="deadbeef")
    # Synthetic verdicts (no network in unit tests).
    r.downgrade = DowngradeResult(verdict=DowngradeVerdict.PREFERS_PQC,
                                  strippable=True, reason="synthetic")
    r.hybrid = HybridCheck(verdict=HybridVerdict.CORRECT, group="X25519MLKEM768")
    return r


def _run_meta():
    return {"timestamp": "2026-06-29T00:00:00+00:00", "profile": "both",
            "policy": {"pack_hashes": conformance.pack_hashes()}}


def test_emit_fresh_cbom_is_well_formed():
    r = _result()
    conformance.evaluate(r, profile="both", run_date=date(2026, 6, 29))
    doc = cbom.build([r], _run_meta())
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.6"
    assert doc["serialNumber"].startswith("urn:uuid:")
    refs = {c["bom-ref"] for c in doc["components"]}
    assert "crypto/protocol/pq.cloudflareresearch.com:443" in refs


def test_serial_is_deterministic():
    r = _result()
    conformance.evaluate(r, profile="both", run_date=date(2026, 6, 29))
    a = cbom.build([r], _run_meta())
    b = cbom.build([r], _run_meta())
    assert a["serialNumber"] == b["serialNumber"]
    # only the metadata timestamp may differ across runs
    import json
    a2 = json.loads(json.dumps(a)); b2 = json.loads(json.dumps(b))
    a2["metadata"]["timestamp"] = b2["metadata"]["timestamp"] = "X"
    assert json.dumps(a2, sort_keys=True) == json.dumps(b2, sort_keys=True)


def test_ingest_enrich_roundtrip_matches_cryptoscan_endpoint():
    fixture = FIXTURES / "cryptoscan-tls.cbom.json"
    if not fixture.is_file():
        pytest.skip("cryptoscan-tls fixture not present")
    r = _result("pq.cloudflareresearch.com")
    conformance.evaluate(r, profile="both", run_date=date(2026, 6, 29))
    doc = cbom.build([r], _run_meta(), cbom_in=str(fixture))
    # tool provenance is chained (CryptoScan carried through)
    tool_names = {t["name"] for t in doc["metadata"]["tools"]["components"]}
    assert "GreyNOC CryptoProbe" in tool_names
    assert "GreyNOC CryptoScan" in tool_names
    # the EXISTING endpoint component was enriched, not duplicated
    eps = [c for c in doc["components"]
           if c["bom-ref"] == "crypto/protocol/pq.cloudflareresearch.com:443"]
    assert len(eps) == 1
    pnames = {p["name"] for p in eps[0]["properties"]}
    assert "greynoc:probe.negotiatedGroup" in pnames
    assert "greynoc:probe.downgradeVerdict" in pnames


def test_ingest_rejects_non_cyclonedx(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"hello": "world"}', encoding="utf-8")
    with pytest.raises(cbom.CBOMError):
        cbom.ingest(str(bad))


@pytest.mark.parametrize("fixture_name", ["cryptoscan-tls.cbom.json"])
def test_emitted_cbom_passes_strict_schema(fixture_name):
    try:
        from cyclonedx.validation.json import JsonStrictValidator
        from cyclonedx.schema import SchemaVersion
    except ImportError:
        pytest.skip("cyclonedx-python-lib not installed ([validation] extra)")
    fixture = FIXTURES / fixture_name
    if not fixture.is_file():
        pytest.skip("fixture not present")
    import json
    r = _result()
    conformance.evaluate(r, profile="both", run_date=date(2026, 6, 29))
    doc = cbom.build([r], _run_meta(), cbom_in=str(fixture))
    errors = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(doc))
    assert errors is None, f"schema errors: {errors}"
