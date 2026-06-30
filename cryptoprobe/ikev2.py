"""
GreyNOC CryptoProbe — IKEv2 / IPsec PQC capability detection (v0.1.0).

This is honest CAPABILITY DETECTION, not validation. We send a real, well-formed
IKE_SA_INIT request (RFC 7296) that advertises INTERMEDIATE_EXCHANGE_SUPPORTED
(RFC 9242) and read the responder's reply to look for PQC-migration signals:

  * an IKEv2 responder is present at all;
  * RFC 9242 IKE_INTERMEDIATE support (the carrier for large PQC key exchanges);
  * RFC 9370 Additional Key Exchange transforms (ADDKE1..ADDKE7, transform types
    33..39) in the responder's selected proposal — the multiple-key-exchange
    mechanism that carries ML-KEM alongside a classical group.

We do NOT complete the exchange, negotiate ADDKE, or verify a PQC key agreement —
so every result carries status ``NOT_YET_VALIDATED`` with a v0.2 roadmap note. We
report only what was observed; absent signals are reported as absent, never as a
negative claim about the peer's true capability (no fabrication).
"""

from __future__ import annotations

import hashlib
import socket
import struct
from dataclasses import dataclass, field

STATUS = "NOT_YET_VALIDATED"
ROADMAP = ("v0.2 roadmap: complete the IKE_INTERMEDIATE exchange (RFC 9242), "
           "negotiate an Additional Key Exchange (RFC 9370), and verify a PQC "
           "(ML-KEM) key agreement end to end.")

# IKEv2 constants (RFC 7296 + IANA).
_EXCH_IKE_SA_INIT = 34
_PL_NONE = 0
_PL_SA = 33
_PL_KE = 34
_PL_NONCE = 40
_PL_NOTIFY = 41
_INTERMEDIATE_EXCHANGE_SUPPORTED = 16438  # RFC 9242 status notify
# Additional Key Exchange transform types (RFC 9370).
_ADDKE_TYPES = set(range(33, 40))  # ADDKE1..ADDKE7
_TRANSFORM_TYPE_NAMES = {
    1: "ENCR", 2: "PRF", 3: "INTEG", 4: "DH",
    33: "ADDKE1", 34: "ADDKE2", 35: "ADDKE3", 36: "ADDKE4",
    37: "ADDKE5", 38: "ADDKE6", 39: "ADDKE7",
}
# Deterministic initiator SPI / nonce for reproducible request bytes.
_SPI_I = hashlib.sha256(b"greynoc-cryptoprobe-ike").digest()[:8]
_NONCE = hashlib.sha256(b"greynoc-cryptoprobe-ike-nonce").digest()


@dataclass
class IKEObservation:
    host: str
    port: int
    responded: bool = False
    responder_spi: str | None = None
    exchange_type: int | None = None
    selected_transforms: list[str] = field(default_factory=list)
    selected_dh_group: int | None = None
    intermediate_exchange_supported: bool | None = None
    additional_key_exchange: list[str] = field(default_factory=list)
    notify_types: list[int] = field(default_factory=list)
    error: str | None = None
    response_sha256: str | None = None
    status: str = STATUS

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "status": self.status,
            "responded": self.responded,
            "responder_spi": self.responder_spi,
            "exchange_type": self.exchange_type,
            "selected_transforms": self.selected_transforms,
            "selected_dh_group": self.selected_dh_group,
            "rfc9242_intermediate_exchange_supported": self.intermediate_exchange_supported,
            "rfc9370_additional_key_exchange": sorted(self.additional_key_exchange),
            "notify_types": sorted(self.notify_types),
            "error": self.error,
            "response_sha256": self.response_sha256,
            "roadmap": ROADMAP,
        }


# --- request construction --------------------------------------------------

def _transform(last: bool, ttype: int, tid: int, attrs: bytes = b"") -> bytes:
    body = struct.pack(">BBH", ttype, 0, tid) + attrs
    return struct.pack(">BBH", 0 if last else 3, 0, 4 + len(body)) + body


def _keylen_attr(bits: int) -> bytes:
    # AF=1 (TV), type=14 (Key Length): 0x800E, value = bits.
    return struct.pack(">HH", 0x800E, bits)


def _sa_payload(next_pl: int) -> bytes:
    transforms = (
        _transform(False, 1, 12, _keylen_attr(256))  # ENCR AES_CBC 256
        + _transform(False, 2, 5)                     # PRF HMAC_SHA2_256
        + _transform(False, 3, 12)                    # INTEG HMAC_SHA2_256_128
        + _transform(True, 4, 14)                     # DH MODP2048 (group 14)
    )
    n_transforms = 4
    proposal_body = struct.pack(">BBBB", 1, 1, 0, n_transforms) + transforms
    proposal = struct.pack(">BBH", 0, 0, 4 + len(proposal_body)) + proposal_body
    return struct.pack(">BBH", next_pl, 0, 4 + len(proposal)) + proposal


def _ke_payload(next_pl: int) -> bytes:
    ke_data = b"\x11" * 256  # MODP2048 public value placeholder (256 bytes)
    body = struct.pack(">HH", 14, 0) + ke_data
    return struct.pack(">BBH", next_pl, 0, 4 + len(body)) + body


def _nonce_payload(next_pl: int) -> bytes:
    return struct.pack(">BBH", next_pl, 0, 4 + len(_NONCE)) + _NONCE


def _notify_intermediate(next_pl: int) -> bytes:
    body = struct.pack(">BBH", 0, 0, _INTERMEDIATE_EXCHANGE_SUPPORTED)
    return struct.pack(">BBH", next_pl, 0, 4 + len(body)) + body


def build_ike_sa_init() -> bytes:
    payloads = (
        _sa_payload(_PL_KE)
        + _ke_payload(_PL_NONCE)
        + _nonce_payload(_PL_NOTIFY)
        + _notify_intermediate(_PL_NONE)
    )
    header = (
        _SPI_I + b"\x00" * 8
        + struct.pack(">BBBBII", _PL_SA, 0x20, _EXCH_IKE_SA_INIT, 0x08, 0,
                      28 + len(payloads))
    )
    return header + payloads


# --- response parsing ------------------------------------------------------

def _parse(data: bytes, obs: IKEObservation) -> None:
    if len(data) < 28:
        obs.error = "short IKE response"
        return
    obs.responder_spi = data[8:16].hex()
    next_pl = data[16]
    obs.exchange_type = data[18]
    off = 28
    end = len(data)
    try:
        while next_pl != _PL_NONE and off + 4 <= end:
            this = next_pl
            next_pl, _, plen = struct.unpack_from(">BBH", data, off)
            if plen < 4 or off + plen > end:
                break
            body = data[off + 4:off + plen]
            if this == _PL_SA:
                _parse_sa(body, obs)
            elif this == _PL_KE and len(body) >= 2:
                obs.selected_dh_group = struct.unpack(">H", body[:2])[0]
            elif this == _PL_NOTIFY and len(body) >= 4:
                _, _, ntype = struct.unpack(">BBH", body[:4])
                obs.notify_types.append(ntype)
                if ntype == _INTERMEDIATE_EXCHANGE_SUPPORTED:
                    obs.intermediate_exchange_supported = True
            off += plen
        if obs.intermediate_exchange_supported is None:
            obs.intermediate_exchange_supported = False
    except (struct.error, IndexError):
        obs.error = "parse error"


def _parse_sa(body: bytes, obs: IKEObservation) -> None:
    off = 0
    while off + 8 <= len(body):
        last, _, plen, _num, _proto, spi_size, n_tr = struct.unpack_from(">BBHBBBB", body, off)
        prop_end = off + plen
        t_off = off + 8 + spi_size
        for _ in range(n_tr):
            if t_off + 8 > len(body):
                break
            t_last, _, t_len, t_type, _r, t_id = struct.unpack_from(">BBHBBH", body, t_off)
            name = _TRANSFORM_TYPE_NAMES.get(t_type, f"type{t_type}")
            obs.selected_transforms.append(f"{name}:{t_id}")
            if t_type in _ADDKE_TYPES:
                obs.additional_key_exchange.append(f"{name}:{t_id}")
            if t_type == 4:
                obs.selected_dh_group = obs.selected_dh_group or t_id
            if t_len < 4:
                break
            t_off += t_len
        if last == 0:
            break
        off = prop_end if plen >= 8 else len(body)


def probe(host: str, port: int = 500, timeout: float = 5.0) -> IKEObservation:
    """Send a real IKE_SA_INIT and report observed PQC-migration signals.

    Never raises; status is always NOT_YET_VALIDATED. No response within the
    timeout is reported as 'no IKEv2 responder observed', not as 'no PQC'."""
    obs = IKEObservation(host=host, port=port)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(build_ike_sa_init(), (host, port))
            data, _ = sock.recvfrom(8192)
        finally:
            sock.close()
    except socket.timeout:
        obs.error = "no IKEv2 responder observed (timeout)"
        return obs
    except OSError as exc:
        obs.error = f"{type(exc).__name__}: {exc}"
        return obs
    obs.responded = True
    obs.response_sha256 = hashlib.sha256(data).hexdigest()
    _parse(data, obs)
    return obs


def run_cli(args, auth) -> int:
    """`cryptoprobe ikev2 <host[:port]>` — honest capability detection."""
    import json
    from . import log, authz as authz_mod
    from .targets import parse_target

    try:
        t = parse_target(args.target, default_port=500)
    except ValueError as exc:
        log.warn(str(exc))
        return 1
    allowed, reason = authz_mod.authorize_target(auth, t.host, t.port)
    if not allowed:
        log.warn(f"refused: {reason}")
        return 3
    log.info(f"IKE_SA_INIT probe: {t.host}:{t.port}  [status: {STATUS}]")
    obs = probe(t.host, t.port, timeout=args.timeout)
    doc = {"ikev2": obs.to_dict(),
           "note": "v0.1.0 capability detection only; see roadmap."}
    if args.format == "json":
        print(json.dumps(doc, indent=2))
    else:
        print(f"=== IKEv2 capability: {t.host}:{t.port} ===")
        print(f"status: {obs.status}")
        if obs.error:
            print(f"  {obs.error}")
        else:
            print(f"  responder present: {obs.responded}")
            print(f"  RFC 9242 IKE_INTERMEDIATE supported: "
                  f"{obs.intermediate_exchange_supported}")
            print(f"  RFC 9370 additional key exchange: "
                  f"{obs.additional_key_exchange or 'none observed'}")
            print(f"  selected transforms: {', '.join(obs.selected_transforms) or 'none'}")
        print(f"  {ROADMAP}")
    return 0
