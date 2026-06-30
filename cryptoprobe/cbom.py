"""
GreyNOC CryptoProbe — CycloneDX 1.6 CBOM ingest / enrich / emit.

Closes the pipeline: CryptoScan (discover) -> migrate -> CryptoProbe (verify +
attest), with the CBOM flowing end to end. We:

  * INGEST a CryptoScan CycloneDX 1.6 CBOM (``--cbom-in``) and carry its
    discovered cryptographic-asset components forward unchanged;
  * ENRICH the matching TLS-endpoint (protocol) component with active-verification
    results (negotiated group, hybrid correctness, downgrade verdict, conformance
    summary), and append CryptoProbe's own observed components;
  * EMIT a valid CycloneDX 1.6 CBOM (``--cbom-out``), deterministic and sorted,
    so two runs over identical inputs differ only in the metadata timestamp.

Schema and ``greynoc:*`` property idioms mirror CryptoScan's ``cbom.py`` so the
two outputs are interchangeable in downstream SBOM tooling. The serialNumber is
derived deterministically (uuid5) — not random — for reproducibility.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from ._version import __version__
from .primitives import NamedGroup

CDX_SPEC = "1.6"
TOOL_NAME = "GreyNOC CryptoProbe"
TOOL_VENDOR = "GreyNOC"
# Fixed namespace so the deterministic serialNumber is stable across machines.
_NS = uuid.UUID("6f0d3c1e-9b2a-5e74-8c11-0a1b2c3d4e5f")


class CBOMError(Exception):
    pass


def ingest(path: str) -> dict:
    """Load + sanity-check a CycloneDX CBOM (e.g. from CryptoScan)."""
    p = Path(path)
    if not p.is_file():
        raise CBOMError(f"CBOM not found: {path}")
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CBOMError(f"CBOM is not valid JSON: {exc}") from exc
    if doc.get("bomFormat") != "CycloneDX":
        raise CBOMError("not a CycloneDX document (bomFormat != 'CycloneDX')")
    if not str(doc.get("specVersion", "")).startswith("1."):
        raise CBOMError(f"unsupported CycloneDX specVersion: {doc.get('specVersion')}")
    doc.setdefault("components", [])
    return doc


def extract_targets(path: str) -> list:
    """Derive probe targets from a CBOM's TLS-endpoint (protocol) components.

    Realizes 'ingest a CryptoScan CBOM and validate its discovered assets':
    every protocol/tls-endpoint locator becomes a target. Returns Target objects
    (sorted, unique). Non-endpoint components are ignored.
    """
    from .targets import parse_target, sorted_unique
    doc = ingest(path)
    locators: set[str] = set()
    for c in doc.get("components", []):
        cp = c.get("cryptoProperties", {})
        if cp.get("assetType") != "protocol":
            continue
        if cp.get("protocolProperties", {}).get("type") not in (None, "tls"):
            continue
        loc = None
        for p in c.get("properties", []):
            if p.get("name") == "greynoc:locator":
                loc = p.get("value")
        if not loc:
            ref = c.get("bom-ref", "")
            if ref.startswith("crypto/protocol/"):
                loc = ref[len("crypto/protocol/"):]
        if not loc:
            occ = c.get("evidence", {}).get("occurrences", [])
            if occ:
                loc = occ[0].get("location")
        if loc:
            locators.add(loc)
    out = []
    for loc in locators:
        try:
            out.append(parse_target(loc))
        except ValueError:
            continue
    return sorted_unique(out)


def _ver(label: str | None) -> str:
    return {
        "TLSv1.3": "1.3", "TLSv1.2": "1.2", "TLSv1.1": "1.1", "TLSv1.0": "1.0",
        "SSLv3": "3.0",
    }.get(label or "", (label or "").replace("TLSv", "")) or "1.3"


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _nist_level_for_group(ng: NamedGroup | None) -> int:
    if ng is None:
        return 0
    if ng.is_hybrid_pqc:
        return ng.nist_category or 0
    return 0  # classical groups and pre-standard drafts assert no NIST PQC level


def _named(name: str | None) -> NamedGroup | None:
    if not name:
        return None
    low = name.lower()
    for g in NamedGroup:
        if g.name.lower() == low:
            return g
    return None


def _conformance_props(result) -> list[dict]:
    if not result.conformance:
        return []
    counts: dict[str, int] = {}
    fails, warns = [], []
    for c in sorted(result.conformance, key=lambda c: c.sort_key):
        counts[c.verdict.value] = counts.get(c.verdict.value, 0) + 1
        tag = f"{c.pack}/{c.rule_id}" + (f"@{c.deadline}" if c.deadline else "")
        if c.verdict.value == "FAIL":
            fails.append(tag)
        elif c.verdict.value == "WARN":
            warns.append(tag)
    summary = ";".join(f"{k}={counts[k]}" for k in sorted(counts))
    props = [{"name": "greynoc:probe.conformance.summary", "value": summary}]
    if fails:
        props.append({"name": "greynoc:probe.conformance.fail",
                      "value": "; ".join(sorted(fails))})
    if warns:
        props.append({"name": "greynoc:probe.conformance.warn",
                      "value": "; ".join(sorted(warns))})
    return props


def _probe_props(result) -> list[dict]:
    g = result.group
    props = [
        {"name": "greynoc:probe.tls13", "value": str(bool(result.is_tls13)).lower()},
        {"name": "greynoc:probe.negotiatedGroup", "value": g.negotiated_group or "unknown"},
        {"name": "greynoc:probe.groupKind", "value": g.group_kind.value},
    ]
    if g.iana_recommended is not None:
        props.append({"name": "greynoc:probe.ianaRecommended",
                      "value": str(g.iana_recommended).lower()})
    if g.nist_category is not None:
        props.append({"name": "greynoc:probe.nistCategory", "value": str(g.nist_category)})
    if result.completed_handshake:
        ch = result.completed_handshake
        props.append({"name": "greynoc:probe.completedHandshake",
                      "value": str(bool(ch.completed)).lower()})
        if ch.transcript_sha256:
            props.append({"name": "greynoc:probe.completedTranscriptSha256",
                          "value": ch.transcript_sha256})
    if result.hybrid:
        props.append({"name": "greynoc:probe.hybridCorrectness",
                      "value": result.hybrid.verdict.value})
    if result.downgrade:
        props.append({"name": "greynoc:probe.downgradeVerdict",
                      "value": result.downgrade.verdict.value})
        if result.downgrade.strippable is not None:
            props.append({"name": "greynoc:probe.downgradeStrippable",
                          "value": str(result.downgrade.strippable).lower()})
    props.extend(_conformance_props(result))
    # transcript provenance (sorted digests of every recorded handshake)
    digs = result.transcript_digests()
    if digs:
        props.append({"name": "greynoc:probe.transcriptCount", "value": str(len(digs))})
    return props


def _endpoint_component(result) -> dict:
    target = result.target
    cipher_suites = []
    if result.completed_handshake and result.completed_handshake.negotiated_cipher:
        cipher_suites.append({"name": result.completed_handshake.negotiated_cipher})
    pp = {"type": "tls", "version": _ver(result.negotiated_version)}
    if cipher_suites:
        pp["cipherSuites"] = cipher_suites
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/protocol/{target}",
        "name": f"TLS {_ver(result.negotiated_version)}",
        "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp},
        "evidence": {"occurrences": [{"location": target}]},
        "properties": [
            {"name": "greynoc:assetType", "value": "tls-endpoint"},
            {"name": "greynoc:locator", "value": target},
        ] + _probe_props(result),
    }


def _kex_component(result) -> dict | None:
    g = result.group
    ng = _named(g.negotiated_group)
    if g.negotiated_group is None:
        return None
    fp = _fingerprint("tls-endpoint", result.target, g.negotiated_group, "kex-group")
    risk = "pq-safe" if (ng and (ng.is_hybrid_pqc or ng.is_draft_pqc)) else "shor-broken"
    comp = {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/{fp}",
        "name": g.negotiated_group,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": "key-agree",
                "executionEnvironment": "software-plain-ram",
                "cryptoFunctions": ["keygen", "keyderive"],
                "nistQuantumSecurityLevel": _nist_level_for_group(ng),
                "parameterSetIdentifier": g.negotiated_group,
            },
        },
        "evidence": {"occurrences": [{"location": result.target}]},
        "properties": [
            {"name": "greynoc:quantumRisk", "value": risk},
            {"name": "greynoc:assetRole", "value": "kex-group"},
            {"name": "greynoc:probe.groupKind", "value": g.group_kind.value},
        ],
    }
    return comp


def _cert_component(result) -> dict | None:
    c = result.cert
    if c is None or c.der_sha256 is None:
        return None
    certprops = {"certificateFormat": "X.509"}
    if c.subject:
        certprops["subjectName"] = str(c.subject)[:300]
    if c.issuer:
        certprops["issuerName"] = str(c.issuer)[:300]
    if c.not_before:
        certprops["notValidBefore"] = str(c.not_before)[:64]
    if c.not_after:
        certprops["notValidAfter"] = str(c.not_after)[:64]
    fp = _fingerprint("certificate", result.target, c.der_sha256)
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/{fp}",
        "name": c.sig_algo or "certificate",
        "cryptoProperties": {"assetType": "certificate", "certificateProperties": certprops},
        "evidence": {"occurrences": [{"location": result.target}]},
        "properties": [
            {"name": "greynoc:assetRole", "value": "certificate"},
            {"name": "greynoc:probe.signatureClass", "value": c.sig_class.value},
            {"name": "greynoc:probe.signatureAlgorithm", "value": c.sig_algo or "unknown"},
            {"name": "greynoc:probe.derSha256", "value": c.der_sha256},
        ],
    }


def build(results, run_meta: dict, cbom_in: str | None = None) -> dict:
    """Build the enriched CBOM. Carries forward an ingested CryptoScan CBOM's
    components and adds CryptoProbe's verified components; deterministic + sorted."""
    ordered = sorted(results, key=lambda r: (r.host, r.port))
    targets = [r.target for r in ordered]

    carried: list[dict] = []
    tools = [{"type": "application", "author": TOOL_VENDOR, "name": TOOL_NAME,
              "version": __version__}]
    ingested_serial = None
    if cbom_in:
        src = ingest(cbom_in)
        carried = list(src.get("components", []))
        ingested_serial = src.get("serialNumber")
        # Preserve CryptoScan's tool provenance in the chain.
        src_tools = (src.get("metadata", {}).get("tools", {}).get("components", []))
        for t in src_tools:
            if t not in tools:
                tools.append(t)

    # Index carried endpoint components so we can enrich rather than duplicate.
    carried_by_ref = {c.get("bom-ref"): c for c in carried}

    new_components: list[dict] = []
    for r in ordered:
        if r.error:
            continue
        ep = _endpoint_component(r)
        existing = carried_by_ref.get(ep["bom-ref"])
        if existing is not None:
            _merge_props(existing, ep["properties"])
            # carry our richer protocolProperties (version/cipherSuites) in.
            existing.setdefault("cryptoProperties", {}).setdefault(
                "protocolProperties", {}).update(
                ep["cryptoProperties"]["protocolProperties"])
        else:
            new_components.append(ep)
        for maker in (_kex_component, _cert_component):
            comp = maker(r)
            if comp and comp["bom-ref"] not in carried_by_ref:
                new_components.append(comp)
                carried_by_ref[comp["bom-ref"]] = comp

    components = _dedupe_sorted(carried + new_components)

    serial = _serial(targets, run_meta, ingested_serial)
    metadata_component = (
        {"type": "application", "name": targets[0], "bom-ref": "target"}
        if len(targets) == 1 else
        {"type": "application", "name": f"{len(targets)} targets", "bom-ref": "target"}
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": run_meta.get("timestamp"),
            "tools": {"components": tools},
            "component": metadata_component,
            "properties": [
                {"name": "greynoc:tool", "value": f"{TOOL_NAME} {__version__}"},
                {"name": "greynoc:scanProfile", "value": run_meta.get("profile", "both")},
                {"name": "greynoc:discipline",
                 "value": "authorized-testing-only;reproducible;no-fabrication"},
                {"name": "greynoc:pipeline",
                 "value": "cryptoscan-discover;cryptoprobe-verify-attest"},
            ],
        },
        "components": components,
    }


def _merge_props(component: dict, new_props: list[dict]) -> None:
    props = component.setdefault("properties", [])
    have = {p.get("name") for p in props}
    for p in new_props:
        if p["name"] not in have:
            props.append(p)


def _dedupe_sorted(components: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for c in components:
        ref = c.get("bom-ref") or _fingerprint("anon", json.dumps(c, sort_keys=True))
        if ref not in seen:
            seen[ref] = c
    return [seen[k] for k in sorted(seen)]


def _serial(targets, run_meta, ingested_serial) -> str:
    pack_hashes = (run_meta.get("policy", {}) or {}).get("pack_hashes", {})
    key = "|".join(sorted(targets))
    key += "|" + "|".join(f"{k}={v}" for k, v in sorted(pack_hashes.items()))
    if ingested_serial:
        key += "|in=" + str(ingested_serial)
    return f"urn:uuid:{uuid.uuid5(_NS, key)}"
