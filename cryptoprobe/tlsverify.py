"""
GreyNOC CryptoProbe — single-target TLS validation.

Produces the base ``ProbeResult`` for one endpoint from observed artifacts only:
  1. raw-socket probe (default browser-like offer) -> negotiated version, selected
     group, cipher; recorded transcript.
  2. an explicit hybrids-only raw probe when the first negotiation wasn't a
     hybrid, to learn whether the server *supports* PQC at all.
  3. certificate fetch via stdlib ssl + ``cryptography`` parse (mirrors
     CryptoScan's ``_key_details``) -> signature/key classification.
  4. a completed handshake via openssl (when available) -> authoritative
     negotiated group from a finished key exchange.

Hybrid-correctness and the downgrade matrix are layered on top by
``downgrade.py``; conformance by ``conformance.py``.
"""

from __future__ import annotations

import socket
import ssl

from . import log
from .primitives import (
    NamedGroup, GroupKind, tls_version_label, tls_below_13, classify_signature,
)
from .model import ProbeResult, GroupObservation, CertInfo, HandshakeRecord
from . import rawprobe, handshake


def _wire_version_label(code: int | None) -> str | None:
    return tls_version_label(code)


def _record_from_raw(method_suffix: str, raw: rawprobe.RawOutcome) -> HandshakeRecord:
    rec = HandshakeRecord(
        method="raw-probe",
        offered_groups=[g.name for g in raw.offered_groups],
        negotiated_version=_wire_version_label(raw.negotiated_version),
        negotiated_group=raw.selected_group_name,
        negotiated_group_code=raw.selected_group,
        negotiated_cipher=None,
        server_share_len=raw.server_share_len,
        is_hrr=raw.is_hrr,
        alert=(f"level={raw.alert[0]} desc={raw.alert[1]}" if raw.alert else None),
        error=raw.error,
        transcript=raw.transcript,
    )
    rec.finalize()
    bits = []
    if raw.selected_group_name:
        bits.append(f"selected {raw.selected_group_name}")
    if raw.is_hrr:
        bits.append("HRR")
    if raw.alert:
        bits.append(f"alert {raw.alert[1]}")
    if raw.error:
        bits.append(raw.error)
    rec.summary = f"[{method_suffix}] " + ("; ".join(bits) or "no response")
    return rec


def validate(host: str, port: int = 443, *, timeout: float = 8.0,
             do_completed: bool = True) -> ProbeResult:
    result = ProbeResult(host=host, port=port)

    # 1. default raw probe -----------------------------------------------------
    raw = rawprobe.probe_offer(host, port, rawprobe.DEFAULT_OFFER, timeout=timeout)
    result.handshakes.append(_record_from_raw("default-offer", raw))
    if raw.error and raw.selected_group is None and raw.negotiated_version is None:
        result.reachable = False
        result.error = raw.error
        return result
    result.reachable = True

    result.negotiated_version = _wire_version_label(raw.negotiated_version)
    result.version_below_13 = tls_below_13(raw.negotiated_version)
    result.is_tls13 = raw.negotiated_version == rawprobe._TLS13_VERSION

    selected = NamedGroup.from_code(raw.selected_group) if raw.selected_group else None
    group = GroupObservation(
        negotiated_group=raw.selected_group_name,
        negotiated_group_code=raw.selected_group,
        group_kind=(selected.kind if selected else GroupKind.UNKNOWN),
        iana_recommended=(selected.iana_recommended if selected else None),
        nist_category=(selected.nist_category if selected else None),
    )
    if selected is not None:
        group.accepted_groups.append(selected.name)
        group.supports_hybrid_pqc = selected.is_hybrid_pqc

    # 2. explicit hybrids-only probe if we didn't already see a hybrid ---------
    if result.is_tls13 and not group.supports_hybrid_pqc:
        hy = rawprobe.probe_offer(host, port, rawprobe.HYBRID_GROUPS, timeout=timeout)
        result.handshakes.append(_record_from_raw("hybrids-only", hy))
        hg = NamedGroup.from_code(hy.selected_group) if hy.selected_group else None
        if hg is not None and hg.is_hybrid_pqc:
            group.supports_hybrid_pqc = True
            if hg.name not in group.accepted_groups:
                group.accepted_groups.append(hg.name)
        elif hy.error is None and hy.alert is None and hg is None:
            group.supports_hybrid_pqc = group.supports_hybrid_pqc or False
        else:
            # refused/alerted when offered only hybrids -> no PQC support observed
            group.supports_hybrid_pqc = group.supports_hybrid_pqc or False
    result.group = group

    # 3. certificate inspection -----------------------------------------------
    result.cert = _fetch_cert(host, port, timeout)

    # 4. completed handshake via openssl --------------------------------------
    if do_completed:
        cap = handshake.capability()
        if cap.available:
            rec = handshake.complete_handshake(host, port, offered_groups=None,
                                               timeout=max(timeout, 10.0))
            result.completed_handshake = rec
            result.handshakes.append(rec)
            # The completed handshake is authoritative for the negotiated group.
            if rec.completed and rec.negotiated_group:
                cg = handshake._group_from_name(rec.negotiated_group)
                if cg is not None:
                    result.group.negotiated_group = cg.name
                    result.group.negotiated_group_code = int(cg)
                    result.group.group_kind = cg.kind
                    result.group.iana_recommended = cg.iana_recommended
                    result.group.nist_category = cg.nist_category
                    if cg.is_hybrid_pqc:
                        result.group.supports_hybrid_pqc = True
                    if cg.name not in result.group.accepted_groups:
                        result.group.accepted_groups.append(cg.name)
        else:
            log.debug(f"completed-handshake evidence UNKNOWN: {cap.detail}")
    return result


def _fetch_cert(host: str, port: int, timeout: float) -> CertInfo | None:
    """Fetch + parse the leaf certificate (CERT_NONE; we observe, not verify)."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        log.debug(f"cert fetch failed for {host}:{port}: {exc}")
        return None
    if not der:
        return None
    return parse_cert_der(der)


def parse_cert_der(der: bytes) -> CertInfo:
    import hashlib
    info = CertInfo(der_sha256=hashlib.sha256(der).hexdigest())
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
    except Exception as exc:  # noqa: BLE001 — never trust a partial parse
        info.subject = f"<unparseable certificate: {type(exc).__name__}>"
        return info
    try:
        info.subject = cert.subject.rfc4514_string()
        info.issuer = cert.issuer.rfc4514_string()
        info.self_signed = cert.subject == cert.issuer
    except Exception:  # noqa: BLE001
        pass
    try:
        info.not_before = cert.not_valid_before_utc.isoformat()
        info.not_after = cert.not_valid_after_utc.isoformat()
    except Exception:  # noqa: BLE001
        pass
    try:
        info.sig_algo = cert.signature_algorithm_oid._name
    except Exception:  # noqa: BLE001
        info.sig_algo = None
    info.sig_class, info.sig_canonical = classify_signature(info.sig_algo)
    _key_details(cert, info)
    return info


def _key_details(cert, info: CertInfo) -> None:
    from cryptography.hazmat.primitives.asymmetric import (
        rsa, ec, ed25519, ed448, dsa,
    )
    try:
        pk = cert.public_key()
    except Exception:  # noqa: BLE001 — e.g. an ML-DSA key cryptography can't load
        info.key_algo = "<unknown>"
        return
    if isinstance(pk, rsa.RSAPublicKey):
        info.key_algo, info.key_size = "RSA", pk.key_size
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        info.key_algo, info.key_size, info.key_curve = "ECDSA", pk.key_size, pk.curve.name
    elif isinstance(pk, ed25519.Ed25519PublicKey):
        info.key_algo, info.key_size, info.key_curve = "EdDSA", 256, "ed25519"
    elif isinstance(pk, ed448.Ed448PublicKey):
        info.key_algo, info.key_size, info.key_curve = "EdDSA", 448, "ed448"
    elif isinstance(pk, dsa.DSAPublicKey):
        info.key_algo, info.key_size = "DSA", pk.key_size
    else:
        info.key_algo = type(pk).__name__
