"""
GreyNOC CryptoProbe — raw-socket TLS 1.3 ClientHello probe.

Adapted from CryptoScan's ``tls13_probe`` (same hand-built ClientHello, same
hardened ServerHello/HelloRetryRequest parser, same deterministic client random
for reproducibility). CryptoProbe extends it in two ways it needs:

  * the full wire transcript (ClientHello sent + every byte received) is captured
    so the engine can SHA-256 it as a provenance artifact; and
  * the server's key_share LENGTH is extracted, which (with the offered-group
    control already present) is what the hybrid-correctness and downgrade-matrix
    logic build on.

This sends a syntactically valid but cryptographically dummy key_share — it
learns the server's *selection* (selected_group / HelloRetryRequest), not a
completed key exchange. Completing the exchange is the openssl path
(``handshake.py``); the two are complementary and both are recorded artifacts.

AUTHORIZED TESTING ONLY. This is a standard, non-exploitative handshake start.
"""

from __future__ import annotations

import hashlib
import socket
import struct
import time
from dataclasses import dataclass, field

from .primitives import NamedGroup, CipherSuite

# TLS record / handshake / extension type codes (RFC 8446).
_CT_CHANGE_CIPHER_SPEC = 0x14
_CT_ALERT = 0x15
_CT_HANDSHAKE = 0x16
_HS_CLIENT_HELLO = 0x01
_HS_SERVER_HELLO = 0x02
_EXT_SERVER_NAME = 0x0000
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_KEY_SHARE = 0x0033
_LEGACY_VERSION = 0x0303
_TLS13_VERSION = 0x0304

# HelloRetryRequest sentinel: ServerHello.random == SHA-256("HelloRetryRequest").
_HRR_RANDOM = bytes.fromhex(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")

# A realistic, browser-like default offer: hybrids first (client preference),
# then classical. Only x25519 ships a (dummy) key_share by default.
DEFAULT_OFFER = (
    NamedGroup.X25519MLKEM768, NamedGroup.SecP256r1MLKEM768,
    NamedGroup.SecP384r1MLKEM1024,
    NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1,
    NamedGroup.x448, NamedGroup.secp521r1, NamedGroup.ffdhe2048,
)
HYBRID_GROUPS = (NamedGroup.X25519MLKEM768, NamedGroup.SecP256r1MLKEM768,
                 NamedGroup.SecP384r1MLKEM1024)
CLASSICAL_GROUPS = (NamedGroup.x25519, NamedGroup.secp256r1,
                    NamedGroup.secp384r1, NamedGroup.x448,
                    NamedGroup.secp521r1, NamedGroup.ffdhe2048)
_DEFAULT_SUITES = (0x1301, 0x1302, 0x1303)


@dataclass
class RawOutcome:
    offered_groups: tuple[NamedGroup, ...]
    is_server_hello: bool = False
    is_hrr: bool = False
    negotiated_version: int | None = None
    selected_group: int | None = None
    server_share_len: int | None = None
    cipher_suite: int | None = None
    alert: tuple[int, int] | None = None
    error: str | None = None
    transcript: bytes = field(default=b"", repr=False)

    @property
    def transcript_sha256(self) -> str | None:
        return hashlib.sha256(self.transcript).hexdigest() if self.transcript else None

    @property
    def selected_group_name(self) -> str | None:
        if self.selected_group is None:
            return None
        g = NamedGroup.from_code(self.selected_group)
        return g.name if g else f"0x{self.selected_group:04X}"


# --- wire helpers (identical idiom to CryptoScan) --------------------------

def _vec(data: bytes, len_bytes: int) -> bytes:
    return len(data).to_bytes(len_bytes, "big") + data


def _extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">H", ext_type) + _vec(data, 2)


def _is_ip_literal(name: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def default_key_shares(groups: tuple[NamedGroup, ...]) -> tuple[NamedGroup, ...]:
    """Pick the key_share group(s) for an offered group set.

    Only x25519's real share is exactly our 32-byte dummy length, so it is the
    one group we can offer a syntactically valid dummy share for. If x25519 is
    offered, send its share; otherwise send NO key_share (an empty, RFC 8446
    §4.2.8-conformant ClientHello) and let the server HelloRetryRequest with its
    preferred group. This avoids sending a key_share for a group that is not in
    supported_groups (which a strict server rejects) or a wrong-length dummy for
    a hybrid group (which an ML-KEM input check rejects).
    """
    return (NamedGroup.x25519,) if NamedGroup.x25519 in groups else ()


def build_client_hello(server_name: str,
                       groups: tuple[NamedGroup, ...] = DEFAULT_OFFER, *,
                       key_share_groups: "tuple[NamedGroup, ...] | None" = None,
                       cipher_suites: tuple[int, ...] = _DEFAULT_SUITES) -> bytes:
    """Build a complete TLS record carrying a TLS 1.3 ClientHello.

    Deterministic client_random (no RNG) so the transcript hashes reproducibly.
    When ``key_share_groups`` is None the shares are derived from ``groups`` so
    every KeyShareEntry corresponds to an offered group (RFC 8446 §4.2.8).
    """
    if key_share_groups is None:
        key_share_groups = default_key_shares(groups)
    client_random = hashlib.sha256(b"greynoc-cryptoprobe-probe").digest()
    # SNI: omit for IP literals (an IP server_name can change server selection);
    # IDNA-encode hostnames so a non-ASCII name is punycoded, not truncated.
    sni_ext = b""
    if not _is_ip_literal(server_name):
        try:
            name_bytes = server_name.encode("idna")[:253]
        except (UnicodeError, ValueError):
            name_bytes = server_name.encode("ascii", "ignore")[:253]
        if name_bytes:
            sni_entry = b"\x00" + _vec(name_bytes, 2)
            sni_ext = _extension(_EXT_SERVER_NAME, _vec(sni_entry, 2))
    sv_ext = _extension(_EXT_SUPPORTED_VERSIONS,
                        _vec(struct.pack(">H", _TLS13_VERSION), 1))
    groups_bytes = b"".join(struct.pack(">H", int(g)) for g in groups)
    sg_ext = _extension(_EXT_SUPPORTED_GROUPS, _vec(groups_bytes, 2))
    sig_algs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0601, 0x0806]
    sa_bytes = b"".join(struct.pack(">H", s) for s in sig_algs)
    sa_ext = _extension(_EXT_SIGNATURE_ALGORITHMS, _vec(sa_bytes, 2))
    entries = b""
    for g in key_share_groups:
        entries += struct.pack(">H", int(g)) + _vec(b"\x2a" * 32, 2)
    ks_ext = _extension(_EXT_KEY_SHARE, _vec(entries, 2))
    extensions = sni_ext + sv_ext + sg_ext + sa_ext + ks_ext
    suites = b"".join(struct.pack(">H", c) for c in cipher_suites)
    body = (struct.pack(">H", _LEGACY_VERSION) + client_random
            + _vec(b"", 1) + _vec(suites, 2) + _vec(b"\x00", 1)
            + _vec(extensions, 2))
    handshake = struct.pack(">B", _HS_CLIENT_HELLO) + _vec(body, 3)
    return (struct.pack(">B", _CT_HANDSHAKE) + struct.pack(">H", _LEGACY_VERSION)
            + _vec(handshake, 2))


def _parse_server_hello(body: bytes) -> tuple[bool, int | None, int | None, int | None, int | None]:
    """Parse a ServerHello/HRR body (after the 4-byte handshake header).

    Returns (is_hrr, negotiated_version, selected_group, server_share_len,
    cipher_suite). On any parse error returns all-None so a malformed message can
    never surface a fabricated group/version.
    """
    try:
        off = 0
        off += 2  # legacy_version
        random = body[off:off + 32]
        off += 32
        is_hrr = random == _HRR_RANDOM
        sid_len = body[off]
        off += 1 + sid_len
        cipher_suite = struct.unpack_from(">H", body, off)[0]
        off += 2
        off += 1  # legacy_compression_method
        ext_total = struct.unpack_from(">H", body, off)[0]
        off += 2
        end = off + ext_total
        if end > len(body):
            raise ValueError("extensions overrun")
        negotiated_version = None
        selected_group = None
        server_share_len = None
        while off + 4 <= end:
            etype, elen = struct.unpack_from(">HH", body, off)
            off += 4
            if off + elen > end:
                raise ValueError("extension length overruns")
            edata = body[off:off + elen]
            off += elen
            if etype == _EXT_SUPPORTED_VERSIONS and len(edata) >= 2:
                negotiated_version = struct.unpack(">H", edata[:2])[0]
            elif etype == _EXT_KEY_SHARE and len(edata) >= 2:
                selected_group = struct.unpack(">H", edata[:2])[0]
                # ServerHello: group(2)+keylen(2)+key. HRR: group(2) only.
                if len(edata) >= 4:
                    klen = struct.unpack(">H", edata[2:4])[0]
                    if 4 + klen <= len(edata):
                        server_share_len = klen
        if negotiated_version is None:
            negotiated_version = _LEGACY_VERSION
        return is_hrr, negotiated_version, selected_group, server_share_len, cipher_suite
    except (IndexError, struct.error, ValueError):
        return False, None, None, None, None


def _drain(buf: bytearray, handshake: bytearray, outcome: RawOutcome) -> bool:
    """Drain whole TLS records from ``buf``; return True once a terminal message
    (ServerHello/HRR or Alert) has been parsed into ``outcome``. Pure byte logic,
    shared by the live socket loop and recorded-transcript replay."""
    while True:
        if len(buf) < 5:
            return False
        ctype = buf[0]
        rec_len = struct.unpack_from(">H", buf, 3)[0]
        if len(buf) < 5 + rec_len:
            return False
        payload = bytes(buf[5:5 + rec_len])
        del buf[:5 + rec_len]
        if ctype == _CT_CHANGE_CIPHER_SPEC:
            continue
        if ctype == _CT_ALERT:
            lvl = payload[0] if payload else 0
            desc = payload[1] if len(payload) > 1 else 0
            outcome.alert = (lvl, desc)
            return True
        if ctype == _CT_HANDSHAKE:
            handshake += payload
            if len(handshake) >= 4:
                hs_type = handshake[0]
                hs_len = int.from_bytes(handshake[1:4], "big")
                if len(handshake) >= 4 + hs_len:
                    if hs_type == _HS_SERVER_HELLO:
                        b = bytes(handshake[4:4 + hs_len])
                        (outcome.is_hrr, outcome.negotiated_version,
                         outcome.selected_group, outcome.server_share_len,
                         outcome.cipher_suite) = _parse_server_hello(b)
                        outcome.is_server_hello = outcome.negotiated_version is not None
                        return True
                    outcome.error = f"unexpected hs {hs_type}"
                    return True
        # other content types -> keep draining


def parse_received(received: bytes,
                   offered_groups: tuple[NamedGroup, ...] = ()) -> RawOutcome:
    """Replay a recorded server response (no socket). Used for recorded-transcript
    integration tests so classification is exercised without the network."""
    outcome = RawOutcome(offered_groups=tuple(offered_groups))
    buf = bytearray(received)
    handshake = bytearray()
    if not _drain(buf, handshake, outcome):
        if outcome.error is None and outcome.alert is None:
            outcome.error = "no ServerHello in transcript"
    outcome.transcript = received
    return outcome


def _read_handshake(host: str, port: int, client_hello: bytes,
                    timeout: float, outcome: RawOutcome) -> None:
    """Send a ClientHello, capture the transcript, parse the first
    ServerHello/HRR (or Alert). Mutates ``outcome`` in place."""
    received = bytearray()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(client_hello)
            buf = bytearray()
            handshake = bytearray()
            end_at = time.monotonic() + timeout
            reads = 0
            while reads < 64:
                remaining = end_at - time.monotonic()
                if remaining <= 0:
                    outcome.error = "timeout"
                    return
                sock.settimeout(remaining)
                chunk = sock.recv(4096)
                if not chunk:
                    break
                received += chunk
                buf += chunk
                reads += 1
                if _drain(buf, handshake, outcome):
                    return
            outcome.error = "no ServerHello"
    except (OSError, socket.timeout) as exc:
        outcome.error = f"{type(exc).__name__}: {exc}"
    finally:
        outcome.transcript = bytes(client_hello) + bytes(received)


def probe_offer(host: str, port: int, groups: tuple[NamedGroup, ...], *,
                key_share_groups: "tuple[NamedGroup, ...] | None" = None,
                cipher_suites: tuple[int, ...] = _DEFAULT_SUITES,
                timeout: float = 8.0) -> RawOutcome:
    """Offer a specific group set and record the outcome. Never raises."""
    outcome = RawOutcome(offered_groups=tuple(groups))
    try:
        ch = build_client_hello(host, groups=groups,
                                key_share_groups=key_share_groups,
                                cipher_suites=cipher_suites)
        _read_handshake(host, port, ch, timeout, outcome)
    except Exception as exc:  # noqa: BLE001 — probe must never raise
        outcome.error = f"{type(exc).__name__}: {exc}"
    return outcome


def enumerate_tls13_ciphers(host: str, port: int, timeout: float = 4.0) -> list[str]:
    """Server's accepted TLS 1.3 cipher suites, by offering each alone."""
    accepted: list[str] = []
    each = min(timeout, 4.0)
    for cs in CipherSuite:
        res = probe_offer(host, port, DEFAULT_OFFER,
                          cipher_suites=(int(cs),), timeout=each)
        if res.error is not None:
            continue  # transient error on one suite must not abort the sweep
        if res.cipher_suite == int(cs):
            accepted.append(cs.name)
    return accepted
