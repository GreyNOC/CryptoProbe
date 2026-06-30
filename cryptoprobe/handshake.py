"""
GreyNOC CryptoProbe — completed-handshake verifier via the system openssl.

The raw-socket probe (``rawprobe.py``) learns the server's *selection* with a
dummy key_share. To honour "active verification, not claims" we also *complete*
a real PQC/hybrid key exchange and read the negotiated group from a finished
handshake. The system ``openssl`` (>= 3.5) negotiates X25519MLKEM768 and the
ML-KEM hybrids natively; we shell out to ``openssl s_client`` with a controlled
``-groups`` offer, capture the whole transcript as a provenance artifact, and
parse the "Negotiated TLS1.3 group" line.

Capability is detected at runtime. If openssl is missing or too old to do PQC,
the completed-handshake evidence is reported UNKNOWN with the reason — never
guessed (no fabrication).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

from .primitives import NamedGroup
from .model import HandshakeRecord

_NEG_GROUP_RE = re.compile(r"Negotiated TLS1\.3 group:\s*(\S+)")
_PROTO_RE = re.compile(r"Protocol\s*:\s*(\S+)")
_NEW_CIPHER_RE = re.compile(r"New,\s*(TLSv[\d.]+),\s*Cipher is\s*(\S+)")
_VERIFY_RE = re.compile(r"Verify return code:\s*(\d+)")


@dataclass
class OpenSSLCapability:
    available: bool
    path: str | None = None
    version: str | None = None
    version_tuple: tuple[int, ...] = ()
    supports_mlkem: bool = False
    supports_ml_dsa: bool = False
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "path": self.path,
            "version": self.version,
            "supports_mlkem_groups": self.supports_mlkem,
            "supports_ml_dsa": self.supports_ml_dsa,
            "detail": self.detail,
        }


_CAP_CACHE: OpenSSLCapability | None = None


def _run(args: list[str], timeout: float, stdin_eof: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        input=b"" if stdin_eof else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def capability(refresh: bool = False) -> OpenSSLCapability:
    """Detect the system openssl and whether it can do ML-KEM / ML-DSA."""
    global _CAP_CACHE
    if _CAP_CACHE is not None and not refresh:
        return _CAP_CACHE
    path = shutil.which("openssl")
    if not path:
        _CAP_CACHE = OpenSSLCapability(False, detail="openssl not found on PATH")
        return _CAP_CACHE
    try:
        ver = _run([path, "version"], timeout=10)
        ver_str = ver.stdout.decode("utf-8", "replace").strip()
        m = re.search(r"(\d+)\.(\d+)\.(\d+)", ver_str)
        vtuple = tuple(int(x) for x in m.groups()) if m else ()
        kems = _run([path, "list", "-kem-algorithms"], timeout=10)
        kem_text = kems.stdout.decode("utf-8", "replace").lower()
        supports_mlkem = ("x25519mlkem768" in kem_text or "ml-kem" in kem_text
                          or "mlkem" in kem_text)
        sigs = _run([path, "list", "-signature-algorithms"], timeout=10)
        sig_text = sigs.stdout.decode("utf-8", "replace").lower()
        supports_ml_dsa = "ml-dsa" in sig_text or "mldsa" in sig_text
        _CAP_CACHE = OpenSSLCapability(
            True, path=path, version=ver_str, version_tuple=vtuple,
            supports_mlkem=supports_mlkem, supports_ml_dsa=supports_ml_dsa,
            detail="ok" if supports_mlkem else "openssl present but no ML-KEM groups")
    except (OSError, subprocess.SubprocessError) as exc:
        _CAP_CACHE = OpenSSLCapability(False, path=path,
                                       detail=f"openssl probe failed: {exc}")
    return _CAP_CACHE


def _openssl_group_token(name: str) -> str:
    """Our NamedGroup names already match openssl's group tokens."""
    return name


def complete_handshake(host: str, port: int,
                       offered_groups: list[NamedGroup] | None = None, *,
                       timeout: float = 10.0) -> HandshakeRecord:
    """Complete a real TLS 1.3 handshake with a controlled group offer.

    Returns a HandshakeRecord. ``completed`` is True only when openssl reports a
    finished handshake; if openssl is unavailable the record carries an error and
    ``completed=None`` (UNKNOWN), never a fabricated success.
    """
    offered_names = [g.name for g in offered_groups] if offered_groups else []
    rec = HandshakeRecord(method="openssl-s_client", offered_groups=offered_names)
    cap = capability()
    if not cap.available:
        rec.error = cap.detail
        rec.completed = None
        return rec

    # Bracket an IPv6 literal for -connect; SNI (-servername) must stay bare and
    # openssl omits SNI for IP literals anyway.
    connect_host = f"[{host}]" if (":" in host and not host.startswith("[")) else host
    args = [cap.path, "s_client", "-connect", f"{connect_host}:{port}",
            "-servername", host, "-tls1_3"]
    if offered_groups:
        args += ["-groups", ":".join(_openssl_group_token(g.name) for g in offered_groups)]
    try:
        proc = _run(args, timeout=timeout)
    except subprocess.TimeoutExpired:
        rec.error = "openssl timeout"
        rec.completed = False
        return rec
    except OSError as exc:
        rec.error = f"openssl exec failed: {exc}"
        rec.completed = None
        return rec

    out = proc.stdout
    rec.transcript = out
    rec.finalize()
    parsed = _parse_openssl_output(out.decode("utf-8", "replace"))
    rec.negotiated_group = parsed["negotiated_group"]
    rec.negotiated_group_code = parsed["negotiated_group_code"]
    rec.negotiated_version = parsed["negotiated_version"]
    rec.negotiated_cipher = parsed["negotiated_cipher"]
    rec.completed = parsed["completed"]
    rec.error = parsed["error"]
    rec.summary = parsed["summary"]
    return rec


def _parse_openssl_output(text: str) -> dict:
    """Parse `openssl s_client` output into handshake facts (pure; testable).

    A handshake is COMPLETE only on direct evidence openssl finished — a
    negotiated-group line, a verify-return-code line, or a cipher line together
    with a peer certificate — AND with no fatal alert present. A bare certificate
    block is not sufficient (a server can present a cert then abort).
    """
    mg = _NEG_GROUP_RE.search(text)
    negotiated_group = negotiated_group_code = None
    if mg:
        negotiated_group = mg.group(1)
        ng = _group_from_name(negotiated_group)
        negotiated_group_code = int(ng) if ng is not None else None
    mp = _PROTO_RE.search(text)
    negotiated_version = mp.group(1) if mp else None
    mc = _NEW_CIPHER_RE.search(text)
    negotiated_cipher = None
    if mc:
        negotiated_version = negotiated_version or mc.group(1)
        negotiated_cipher = mc.group(2)
    mv = _VERIFY_RE.search(text)

    # Match openssl's own alert/failure phrasing (e.g. "tlsv1 alert handshake
    # failure", "sslv3 alert ...", "no shared cipher") rather than a bare "alert"
    # substring, which could appear inside a certificate subject.
    has_fatal_alert = re.search(
        r"(ssl|tls)\w* alert|handshake failure|no shared cipher|no peer certificate",
        text, re.IGNORECASE) is not None
    finished = bool(mg) or (mv is not None) or (mc is not None and "BEGIN CERTIFICATE" in text)
    completed = finished and not has_fatal_alert

    error = None if completed else _failure_reason(text)
    parts = []
    if negotiated_group:
        parts.append(f"group {negotiated_group}")
    if negotiated_cipher:
        parts.append(f"cipher {negotiated_cipher}")
    if mv:
        parts.append(f"verify {mv.group(1)}")
    summary = "; ".join(parts) if parts else (error or "no handshake")
    return {
        "negotiated_group": negotiated_group,
        "negotiated_group_code": negotiated_group_code,
        "negotiated_version": negotiated_version,
        "negotiated_cipher": negotiated_cipher,
        "completed": completed,
        "error": error,
        "summary": summary,
    }


def _group_from_name(name: str) -> NamedGroup | None:
    low = name.strip().lower()
    for g in NamedGroup:
        if g.name.lower() == low:
            return g
    return None


def _failure_reason(text: str) -> str:
    for needle in ("no shared cipher", "handshake failure", "sslv3 alert",
                   "tlsv1 alert", "alert", "no peer certificate",
                   "connect:errno", "unable to get local issuer"):
        m = re.search(rf"[^\n]*{re.escape(needle)}[^\n]*", text, re.IGNORECASE)
        if m:
            return m.group(0).strip()[:200]
    return "handshake did not complete"
