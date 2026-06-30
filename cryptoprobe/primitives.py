"""
GreyNOC CryptoProbe — cryptographic primitive + TLS group knowledge base.

This is the single source of truth for how CryptoProbe classifies what it
observes on the wire. It deliberately mirrors the token vocabulary of CryptoScan
(``cryptoscan/primitives.py``) — same ``Severity`` ranks, same group names, same
PQC parameter-set categories — so a CBOM produced by CryptoScan and enriched by
CryptoProbe round-trips without token drift. CryptoProbe vendors the subset it
needs rather than importing CryptoScan, to stay a self-contained single artifact
for air-gapped / Termux field operators (an offline-capability requirement).

No fabrication: every code point, parameter size and security category below is
traceable to a public registry/standard. The TLS Supported Groups code points
are the IANA registry values (draft-ietf-tls-ecdhe-mlkem; the obsolete Kyber
draft groups from draft-tls-westerbaan-xyber768d00). The ML-KEM ciphertext and
ECDHE share sizes are from FIPS 203 / RFC 7748 / SEC 1.
"""

from __future__ import annotations

from enum import Enum, IntEnum


class Severity(str, Enum):
    """Identical ranks to CryptoScan so the shared CI gate behaves the same."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]


class QuantumRisk(str, Enum):
    SHOR = "shor-broken"          # asymmetric, broken by Shor (HNDL liability)
    GROVER = "grover-weakened"    # symmetric, halved by Grover
    SAFE = "pq-safe"              # standardized PQC / adequate symmetric
    LEGACY = "classically-weak"   # already broken/deprecated, pre-quantum
    UNKNOWN = "unknown"


# CycloneDX 1.6 cryptoProperties.algorithmProperties.primitive vocabulary.
class Primitive(str, Enum):
    PKE = "pke"
    SIGNATURE = "signature"
    KEY_AGREE = "key-agree"
    BLOCK_CIPHER = "block-cipher"
    STREAM_CIPHER = "stream-cipher"
    HASH = "hash"
    MAC = "mac"
    KDF = "kdf"
    DRBG = "drbg"
    OTHER = "other"


class GroupKind(str, Enum):
    """How a negotiated TLS 1.3 key-exchange group classifies for PQC posture."""
    HYBRID_PQC = "hybrid-pqc"      # standardized ECDHE + ML-KEM hybrid
    DRAFT_PQC = "draft-pqc"        # obsolete pre-standard Kyber-draft hybrid
    PURE_PQC = "pure-pqc"          # standalone ML-KEM (no standardized TLS group yet)
    CLASSICAL = "classical"        # ECDHE / FFDHE only — Shor-broken, HNDL-exposed
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# TLS Supported Groups (IANA registry). Only code points we can cite are listed;
# an unknown code observed on the wire is reported by its raw 0xXXXX value and
# classified UNKNOWN — never guessed (no fabrication).
# ---------------------------------------------------------------------------
class NamedGroup(IntEnum):
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    x25519 = 0x001D
    x448 = 0x001E
    ffdhe2048 = 0x0100
    ffdhe3072 = 0x0101
    ffdhe4096 = 0x0102
    # Standardized post-quantum hybrids (draft-ietf-tls-ecdhe-mlkem).
    SecP256r1MLKEM768 = 0x11EB   # IANA Recommended = N
    X25519MLKEM768 = 0x11EC      # IANA Recommended = Y
    SecP384r1MLKEM1024 = 0x11ED  # IANA Recommended = N
    # Obsolete pre-standard Kyber draft groups (draft-tls-westerbaan-xyber768d00).
    X25519Kyber768Draft00 = 0x6399
    SecP256r1Kyber768Draft00 = 0x639A   # correct IANA name; "P256..." is shorthand

    @classmethod
    def from_code(cls, code: int) -> "NamedGroup | None":
        try:
            return cls(code)
        except ValueError:
            return None

    @property
    def kind(self) -> GroupKind:
        if self in _HYBRID_PQC_GROUPS:
            return GroupKind.HYBRID_PQC
        if self in _DRAFT_PQC_GROUPS:
            return GroupKind.DRAFT_PQC
        return GroupKind.CLASSICAL

    @property
    def is_hybrid_pqc(self) -> bool:
        return self in _HYBRID_PQC_GROUPS

    @property
    def is_draft_pqc(self) -> bool:
        return self in _DRAFT_PQC_GROUPS

    @property
    def is_classical(self) -> bool:
        return self.kind is GroupKind.CLASSICAL

    @property
    def iana_recommended(self) -> bool:
        """Only X25519MLKEM768 carries Recommended=Y in the IANA registry."""
        return self is NamedGroup.X25519MLKEM768

    @property
    def classifier_token(self) -> str:
        """Lowercase token matching CryptoScan's registry, for CBOM round-trip."""
        return _GROUP_TOKEN.get(self, self.name.lower())

    @property
    def ml_kem_param(self) -> str | None:
        """The ML-KEM parameter set inside this hybrid/draft group, if any."""
        return _GROUP_MLKEM.get(self)

    @property
    def classical_component(self) -> str | None:
        return _GROUP_CLASSICAL_COMPONENT.get(self)

    @property
    def nist_category(self) -> int | None:
        """NIST PQC security category (1/3/5) of the ML-KEM half, if any.

        ML-KEM-768 is category 3; ML-KEM-1024 is category 5 (FIPS 203). CNSA 2.0
        requires the category-5 ML-KEM-1024 path.
        """
        return _GROUP_CATEGORY.get(self)

    @property
    def expected_server_share_len(self) -> int | None:
        """Expected ServerHello key_share length (bytes) for a hybrid group.

        Used by the hybrid-correctness check to catch a server that names a
        hybrid but returns a malformed/short share. ML-KEM ciphertext sizes are
        from FIPS 203 (ML-KEM-768 = 1088 B, ML-KEM-1024 = 1568 B); ECDHE share
        sizes are the uncompressed point / scalar lengths (X25519 = 32,
        secp256r1 = 65, secp384r1 = 97).
        """
        return _GROUP_SERVER_SHARE_LEN.get(self)


_HYBRID_PQC_GROUPS = frozenset({
    NamedGroup.SecP256r1MLKEM768,
    NamedGroup.X25519MLKEM768,
    NamedGroup.SecP384r1MLKEM1024,
})
_DRAFT_PQC_GROUPS = frozenset({
    NamedGroup.X25519Kyber768Draft00,
    NamedGroup.SecP256r1Kyber768Draft00,
})

_GROUP_TOKEN = {
    NamedGroup.secp256r1: "ecdh",
    NamedGroup.secp384r1: "ecdh",
    NamedGroup.secp521r1: "ecdh",
    NamedGroup.x25519: "x25519",
    NamedGroup.x448: "x448",
    NamedGroup.ffdhe2048: "ffdhe2048",
    NamedGroup.ffdhe3072: "ffdhe3072",
    NamedGroup.ffdhe4096: "dh",
    NamedGroup.SecP256r1MLKEM768: "secp256r1mlkem768",
    NamedGroup.X25519MLKEM768: "x25519mlkem768",
    NamedGroup.SecP384r1MLKEM1024: "secp384r1mlkem1024",
    NamedGroup.X25519Kyber768Draft00: "x25519kyber768draft00",
    NamedGroup.SecP256r1Kyber768Draft00: "secp256r1kyber768draft00",
}
_GROUP_MLKEM = {
    NamedGroup.SecP256r1MLKEM768: "ML-KEM-768",
    NamedGroup.X25519MLKEM768: "ML-KEM-768",
    NamedGroup.SecP384r1MLKEM1024: "ML-KEM-1024",
    NamedGroup.X25519Kyber768Draft00: "Kyber-768 (draft)",
    NamedGroup.SecP256r1Kyber768Draft00: "Kyber-768 (draft)",
}
_GROUP_CLASSICAL_COMPONENT = {
    NamedGroup.SecP256r1MLKEM768: "secp256r1",
    NamedGroup.X25519MLKEM768: "x25519",
    NamedGroup.SecP384r1MLKEM1024: "secp384r1",
    NamedGroup.X25519Kyber768Draft00: "x25519",
    NamedGroup.SecP256r1Kyber768Draft00: "secp256r1",
}
_GROUP_CATEGORY = {
    NamedGroup.SecP256r1MLKEM768: 3,
    NamedGroup.X25519MLKEM768: 3,
    NamedGroup.SecP384r1MLKEM1024: 5,
}
# total = ECDHE share + ML-KEM ciphertext
_GROUP_SERVER_SHARE_LEN = {
    NamedGroup.X25519MLKEM768: 32 + 1088,        # 1120
    NamedGroup.SecP256r1MLKEM768: 65 + 1088,     # 1153
    NamedGroup.SecP384r1MLKEM1024: 97 + 1568,    # 1665
}


# ---------------------------------------------------------------------------
# TLS 1.3 cipher suites (IANA / RFC 8446). For CNSA 2.0 we care that the bulk
# cipher is AES-256 and the hash is SHA-384/512.
# ---------------------------------------------------------------------------
class CipherSuite(IntEnum):
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305

    @classmethod
    def from_code(cls, code: int) -> "CipherSuite | None":
        try:
            return cls(code)
        except ValueError:
            return None


# suite -> (bulk cipher token, bulk bits, hash token, hash bits)
CIPHER_SUITE_FACTS: dict[CipherSuite, tuple[str, int, str, int]] = {
    CipherSuite.TLS_AES_128_GCM_SHA256: ("AES-128", 128, "SHA-256", 256),
    CipherSuite.TLS_AES_256_GCM_SHA384: ("AES-256", 256, "SHA-384", 384),
    CipherSuite.TLS_CHACHA20_POLY1305_SHA256: ("ChaCha20", 256, "SHA-256", 256),
    CipherSuite.TLS_AES_128_CCM_SHA256: ("AES-128", 128, "SHA-256", 256),
    CipherSuite.TLS_AES_128_CCM_8_SHA256: ("AES-128", 128, "SHA-256", 256),
}


# ---------------------------------------------------------------------------
# Certificate / handshake signature-algorithm classification.
# ---------------------------------------------------------------------------
class SigClass(str, Enum):
    CLASSICAL = "classical"        # RSA / ECDSA / EdDSA / DSA — Shor-broken
    PQC = "pqc"                    # ML-DSA / SLH-DSA / FN-DSA
    COMPOSITE = "composite"        # composite/hybrid PQ+classical certificate
    UNKNOWN = "unknown"


# Normalized PQ signature tokens we recognize -> canonical name.
_PQC_SIG_TOKENS = {
    "ml-dsa-44": "ML-DSA-44", "mldsa44": "ML-DSA-44", "ml-dsa44": "ML-DSA-44",
    "ml-dsa-65": "ML-DSA-65", "mldsa65": "ML-DSA-65", "ml-dsa65": "ML-DSA-65",
    "ml-dsa-87": "ML-DSA-87", "mldsa87": "ML-DSA-87", "ml-dsa87": "ML-DSA-87",
    "dilithium2": "ML-DSA-44", "dilithium3": "ML-DSA-65", "dilithium5": "ML-DSA-87",
    "slh-dsa-sha2-128s": "SLH-DSA-SHA2-128s", "slh-dsa-sha2-128f": "SLH-DSA-SHA2-128f",
    "slh-dsa-sha2-192s": "SLH-DSA-SHA2-192s", "slh-dsa-sha2-192f": "SLH-DSA-SHA2-192f",
    "slh-dsa-sha2-256s": "SLH-DSA-SHA2-256s", "slh-dsa-sha2-256f": "SLH-DSA-SHA2-256f",
    "slh-dsa-shake-128s": "SLH-DSA-SHAKE-128s", "slh-dsa-shake-128f": "SLH-DSA-SHAKE-128f",
    "slh-dsa-shake-192s": "SLH-DSA-SHAKE-192s", "slh-dsa-shake-192f": "SLH-DSA-SHAKE-192f",
    "slh-dsa-shake-256s": "SLH-DSA-SHAKE-256s", "slh-dsa-shake-256f": "SLH-DSA-SHAKE-256f",
    "sphincs+": "SLH-DSA", "falcon512": "FN-DSA-512", "falcon1024": "FN-DSA-1024",
}

# Classical signature OID-name / token fragments -> canonical algorithm token.
_CLASSICAL_SIG_FRAGMENTS = (
    ("rsassa-pss", "RSA"), ("rsaencryption", "RSA"), ("withrsa", "RSA"),
    ("rsa", "RSA"),
    ("ecdsa", "ECDSA"), ("withecdsa", "ECDSA"),
    ("ed25519", "Ed25519"), ("ed448", "Ed448"),
    ("dsa", "DSA"),
)


def classify_signature(name: str | None) -> tuple[SigClass, str | None]:
    """Classify a certificate/handshake signature algorithm name or OID-name.

    Returns (SigClass, canonical_token). UNKNOWN/None token when unrecognized —
    we never coerce an unknown signature into a class.
    """
    if not name:
        return SigClass.UNKNOWN, None
    low = name.strip().lower().replace("_", "-")
    flat = low.replace("-", "")

    # Resolve the PQC half (if any) first.
    pqc_canon = None
    for tok, canon in _PQC_SIG_TOKENS.items():
        if tok.replace("-", "") in flat:
            pqc_canon = canon
            break
    has_pqc = pqc_canon is not None

    # Detect a *genuine* classical co-algorithm. Mask the PQC family names so the
    # 'dsa' inside 'ml-dsa'/'slh-dsa'/'fn-dsa' is not mistaken for classical DSA.
    masked = low
    for fam in ("ml-dsa", "mldsa", "slh-dsa", "slhdsa", "fn-dsa", "fndsa",
                "dilithium", "sphincs+", "sphincs", "falcon"):
        masked = masked.replace(fam, " ")
    classical_canon = None
    for frag, canon in _CLASSICAL_SIG_FRAGMENTS:
        if frag in masked:
            classical_canon = canon
            break
    has_classical = classical_canon is not None

    if "composite" in low or (has_pqc and has_classical):
        return SigClass.COMPOSITE, name
    if has_pqc:
        return SigClass.PQC, pqc_canon
    if has_classical:
        return SigClass.CLASSICAL, classical_canon
    return SigClass.UNKNOWN, None


# PQC parameter set -> NIST security category (1..5). FIPS 203/204/205, FIPS 206
# (draft). Mirrors CryptoScan's PQC_PARAM_SETS.
PQC_PARAM_SETS: dict[str, int] = {
    "ml-kem-512": 1, "ml-kem-768": 3, "ml-kem-1024": 5,
    "ml-dsa-44": 2, "ml-dsa-65": 3, "ml-dsa-87": 5,
    "slh-dsa-128s": 1, "slh-dsa-128f": 1,
    "slh-dsa-192s": 3, "slh-dsa-192f": 3,
    "slh-dsa-256s": 5, "slh-dsa-256f": 5,
    "falcon-512": 1, "falcon-1024": 5,
    "fn-dsa-512": 1, "fn-dsa-1024": 5,
}


def pqc_category(canonical_name: str | None) -> int | None:
    """NIST security category for a canonical PQC name like 'ML-DSA-87'."""
    if not canonical_name:
        return None
    low = canonical_name.strip().lower()
    if low in PQC_PARAM_SETS:
        return PQC_PARAM_SETS[low]
    # SLH-DSA-SHA2-256s -> slh-dsa-256s
    flat = low.replace("slh-dsa-sha2-", "slh-dsa-").replace("slh-dsa-shake-", "slh-dsa-")
    return PQC_PARAM_SETS.get(flat)


# ---------------------------------------------------------------------------
# TLS protocol versions.
# ---------------------------------------------------------------------------
# Wire code -> human label.
TLS_VERSIONS: dict[int, str] = {
    0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1",
    0x0303: "TLSv1.2", 0x0304: "TLSv1.3",
}
TLS13 = 0x0304


def tls_version_label(code: int | None) -> str | None:
    if code is None:
        return None
    return TLS_VERSIONS.get(code, f"0x{code:04X}")


def tls_below_13(code: int | None) -> bool | None:
    """True if a *known* version below TLS 1.3 (EO 14306 flags these). None if
    the version is unknown — never guess."""
    if code is None:
        return None
    if code in TLS_VERSIONS:
        return code < TLS13
    return None
