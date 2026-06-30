"""Signed attestation: ML-DSA-87 + Ed25519 sign/verify/tamper. No network.

(openssl genpkey/pkeyutl are local operations, not network.)
"""

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest

from cryptoprobe import attest, handshake, manifest as manifest_mod
from cryptoprobe.model import ProbeResult


def _manifest():
    doc = {
        "run": {"tool": {"name": "GreyNOC CryptoProbe", "version": "0.1.0"},
                "timestamp": "2026-06-29T00:00:00+00:00", "profile": "both",
                "authorization": {"identifier": "OP-1", "source": "flag"}},
        "summary": {"targets": 1},
        "targets": [{"target": "x:443", "group": {"negotiated_group": "X25519MLKEM768"}}],
    }
    r = ProbeResult(host="x", port=443)
    return manifest_mod.build(doc, [r], args=None)


def _roundtrip(algorithm, tmp_path):
    priv = tmp_path / f"{algorithm}.key"
    attest.generate_keypair(algorithm, str(priv))
    man = _manifest()
    att = attest.sign(man, str(priv), algorithm)
    # embedded-key check: cryptographically ok, but NOT authenticated (#3)
    ok, _, authenticated = attest.verify(att)
    assert ok and authenticated is False
    # tamper the embedded manifest -> verification must fail
    tampered = copy.deepcopy(att)
    tampered["manifest"]["summary"]["targets"] = 999
    ok2, _, _ = attest.verify(tampered)
    assert ok2 is False
    return att, str(priv)


def test_ed25519_sign_verify_tamper(tmp_path):
    att, priv = _roundtrip("ed25519", tmp_path)
    assert att["signing"]["algorithm"] == "Ed25519"
    # with the operator's trusted public key, it authenticates (exit-0 path)
    pub = tmp_path / "ed.pub"
    pub.write_bytes(attest._ed25519_public_pem(priv))
    ok, _, authenticated = attest.verify(att, str(pub))
    assert ok and authenticated is True


def test_ml_dsa_87_sign_verify_tamper(tmp_path):
    cap = handshake.capability()
    if not (cap.available and cap.supports_ml_dsa):
        pytest.skip("openssl with ML-DSA not available")
    att, _ = _roundtrip("ml-dsa-87", tmp_path)
    assert att["signing"]["algorithm"] == "ML-DSA-87"
    # the signature is the real ML-DSA-87 size (~4627 bytes)
    import base64
    assert len(base64.b64decode(att["signature_b64"])) > 4000


def test_verify_with_wrong_key_fails(tmp_path):
    priv = tmp_path / "ed25519.key"
    attest.generate_keypair("ed25519", str(priv))
    att = attest.sign(_manifest(), str(priv), "ed25519")
    # a different key's public material must not verify
    other = tmp_path / "other.key"
    other_pub_pem = attest.generate_keypair("ed25519", str(other))
    other_pub = tmp_path / "other.pub"
    other_pub.write_bytes(other_pub_pem)
    ok, _, authenticated = attest.verify(att, str(other_pub))
    assert ok is False and authenticated is False


def test_manifest_binds_findings_reproducibly():
    # results_sha256 excludes the timestamp -> stable across runs
    doc1 = {"run": {"timestamp": "A"}, "summary": {"n": 1}, "targets": []}
    doc2 = {"run": {"timestamp": "B"}, "summary": {"n": 1}, "targets": []}
    assert manifest_mod.results_digest(doc1) == manifest_mod.results_digest(doc2)
    doc3 = {"run": {"timestamp": "A"}, "summary": {"n": 2}, "targets": []}
    assert manifest_mod.results_digest(doc1) != manifest_mod.results_digest(doc3)
