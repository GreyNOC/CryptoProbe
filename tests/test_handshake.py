"""openssl-output parsing, completion gating, capability detection. No network."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoprobe import handshake, rawprobe
from cryptoprobe.primitives import NamedGroup

_SUCCESS = """CONNECTED(00000003)
depth=2 C = US, O = Example
verify return:1
Negotiated TLS1.3 group: X25519MLKEM768
-----BEGIN CERTIFICATE-----
MIIBpacefoo
-----END CERTIFICATE-----
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
Verify return code: 0 (ok)
"""

# A server that presents a certificate then aborts the handshake (no group, no
# verify line, a fatal alert) must NOT be reported as completed (finding #25).
_CERT_THEN_ABORT = """CONNECTED(00000003)
-----BEGIN CERTIFICATE-----
MIIBpacefoo
-----END CERTIFICATE-----
140735.. tlsv1 alert handshake failure
"""

_NO_SHARED = """CONNECTED(00000003)
no shared cipher
"""


def test_parse_success():
    p = handshake._parse_openssl_output(_SUCCESS)
    assert p["completed"] is True
    assert p["negotiated_group"] == "X25519MLKEM768"
    assert p["negotiated_group_code"] == 0x11EC
    assert p["negotiated_cipher"] == "TLS_AES_256_GCM_SHA384"
    assert p["error"] is None


def test_cert_then_abort_is_not_completed():
    p = handshake._parse_openssl_output(_CERT_THEN_ABORT)
    assert p["completed"] is False
    assert "handshake failure" in p["error"]


def test_no_shared_cipher_is_failure():
    p = handshake._parse_openssl_output(_NO_SHARED)
    assert p["completed"] is False
    assert "no shared cipher" in p["error"]


def test_empty_output():
    p = handshake._parse_openssl_output("")
    assert p["completed"] is False
    assert p["summary"]


def test_group_from_name_case_insensitive():
    assert handshake._group_from_name("x25519mlkem768") is NamedGroup.X25519MLKEM768
    assert handshake._group_from_name("nope") is None


def test_capability_handles_missing_openssl(monkeypatch):
    monkeypatch.setattr(handshake.shutil, "which", lambda _: None)
    handshake._CAP_CACHE = None
    try:
        cap = handshake.capability(refresh=True)
        assert cap.available is False
        assert "not found" in cap.detail
        # complete_handshake reports UNKNOWN (completed is None), never fabricated
        rec = handshake.complete_handshake("h", 443, timeout=1)
        assert rec.completed is None
        assert rec.error == cap.detail
    finally:
        handshake._CAP_CACHE = None


def test_hybrids_only_clienthello_keyshare_is_subset_of_offered():
    # finding #2: every KeyShareEntry group must be in supported_groups (RFC 8446
    # §4.2.8). For a hybrids-only offer that means an EMPTY key_share.
    assert rawprobe.default_key_shares(rawprobe.HYBRID_GROUPS) == ()
    assert NamedGroup.x25519 in rawprobe.default_key_shares(rawprobe.DEFAULT_OFFER)
    assert NamedGroup.x25519 in rawprobe.default_key_shares(rawprobe.CLASSICAL_GROUPS)
