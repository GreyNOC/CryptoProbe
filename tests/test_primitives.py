"""Primitive / group classification (Phase 1 foundation). No network."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptoprobe.primitives import (
    NamedGroup, GroupKind, Severity, SigClass, classify_signature,
    CipherSuite, CIPHER_SUITE_FACTS, tls_below_13, tls_version_label,
    pqc_category,
)


def test_group_codepoints_match_iana():
    # The three standardized hybrids (draft-ietf-tls-ecdhe-mlkem).
    assert int(NamedGroup.SecP256r1MLKEM768) == 0x11EB
    assert int(NamedGroup.X25519MLKEM768) == 0x11EC
    assert int(NamedGroup.SecP384r1MLKEM1024) == 0x11ED
    # Obsolete Kyber drafts; 0x639A is SecP256r1Kyber768Draft00 (not "P256...").
    assert int(NamedGroup.X25519Kyber768Draft00) == 0x6399
    assert int(NamedGroup.SecP256r1Kyber768Draft00) == 0x639A


def test_group_classification():
    assert NamedGroup.X25519MLKEM768.kind is GroupKind.HYBRID_PQC
    assert NamedGroup.X25519MLKEM768.iana_recommended is True
    assert NamedGroup.SecP256r1MLKEM768.iana_recommended is False
    assert NamedGroup.SecP384r1MLKEM1024.nist_category == 5   # ML-KEM-1024
    assert NamedGroup.X25519MLKEM768.nist_category == 3       # ML-KEM-768
    assert NamedGroup.X25519Kyber768Draft00.kind is GroupKind.DRAFT_PQC
    assert NamedGroup.x25519.kind is GroupKind.CLASSICAL
    assert NamedGroup.from_code(0x9999) is None


def test_expected_hybrid_share_lengths():
    # ML-KEM ciphertext (FIPS 203) + ECDHE share.
    assert NamedGroup.X25519MLKEM768.expected_server_share_len == 1120
    assert NamedGroup.SecP256r1MLKEM768.expected_server_share_len == 1153
    assert NamedGroup.SecP384r1MLKEM1024.expected_server_share_len == 1665
    assert NamedGroup.x25519.expected_server_share_len is None


def test_signature_classification():
    assert classify_signature("sha256WithRSAEncryption")[0] is SigClass.CLASSICAL
    assert classify_signature("ecdsa-with-SHA384")[0] is SigClass.CLASSICAL
    assert classify_signature("ed25519")[0] is SigClass.CLASSICAL
    assert classify_signature("ML-DSA-87") == (SigClass.PQC, "ML-DSA-87")
    assert classify_signature("id-ml-dsa-65")[0] is SigClass.PQC
    assert classify_signature("SLH-DSA-SHA2-256s")[0] is SigClass.PQC
    # composite naming both halves
    assert classify_signature("MLDSA65-ECDSA-P256-SHA256")[0] is SigClass.COMPOSITE
    assert classify_signature("totally-unknown-alg")[0] is SigClass.UNKNOWN
    assert classify_signature(None)[0] is SigClass.UNKNOWN


def test_cipher_suite_facts_for_cnsa():
    bulk, bits, hsh, _ = CIPHER_SUITE_FACTS[CipherSuite.TLS_AES_256_GCM_SHA384]
    assert (bulk, bits, hsh) == ("AES-256", 256, "SHA-384")   # CNSA-grade
    bulk, bits, hsh, _ = CIPHER_SUITE_FACTS[CipherSuite.TLS_AES_128_GCM_SHA256]
    assert bulk == "AES-128"   # below CNSA floor


def test_tls_version_helpers():
    assert tls_version_label(0x0304) == "TLSv1.3"
    assert tls_below_13(0x0303) is True
    assert tls_below_13(0x0304) is False
    assert tls_below_13(None) is None


def test_pqc_category():
    assert pqc_category("ML-DSA-87") == 5
    assert pqc_category("ML-KEM-1024") == 5
    assert pqc_category("SLH-DSA-SHA2-256s") == 5
    assert pqc_category("ML-DSA-44") == 2
    assert pqc_category(None) is None


def test_severity_rank_matches_cryptoscan():
    assert Severity.CRITICAL.rank == 4
    assert Severity.INFO.rank == 0
    assert Severity.HIGH.rank > Severity.MEDIUM.rank
