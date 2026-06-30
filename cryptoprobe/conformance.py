"""
GreyNOC CryptoProbe — declarative conformance engine.

Verdicts are data, not code: the bundled YAML packs (``packs/*.yaml``) declare
requirements as predicates over a fixed set of *observed facts* extracted from a
ProbeResult. A new mandate is a new pack — no code change. Every fact is
tri-state aware so a requirement that cannot be evaluated from what we observed
returns UNKNOWN, never a guessed PASS/FAIL (no fabrication).

Profile selection:
  nss       -> CNSA 2.0 (+ general packs: FIPS 140-3, NIST IR 8547)
  civilian  -> OMB M-26-15 (+ general packs)
  both      -> CNSA 2.0 AND OMB M-26-15 (+ general) — surfaces the SLH-DSA
               NSS-vs-civilian divergence, labeled by pack.

Provenance: every pack file is hashed (CRLF-normalized) and the hashes are
checked against packs/PROVENANCE.json by ``policy verify`` and recorded in the
run manifest.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone
from functools import lru_cache
from pathlib import Path

import yaml

from .primitives import Severity, NamedGroup, CipherSuite, CIPHER_SUITE_FACTS
from .model import ConformanceVerdict, ConformanceFinding

_PACKS_DIR = Path(__file__).resolve().parent / "packs"
_FIPS_140_2_HISTORICAL = date(2026, 9, 21)

# tri-state
_T, _F, _U = "TRUE", "FALSE", "UNKNOWN"

_PROFILE_SELECT = {
    "nss": {"nss", "general"},
    "civilian": {"civilian", "general"},
    "both": {"nss", "civilian", "general"},
}


# --- loading ---------------------------------------------------------------

def _pack_files() -> list[Path]:
    return sorted(p for p in _PACKS_DIR.glob("*.yaml"))


@lru_cache(maxsize=1)
def load_packs() -> tuple[dict, ...]:
    packs = []
    for p in _pack_files():
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        doc["_file"] = p.name
        packs.append(doc)
    return tuple(sorted(packs, key=lambda d: d["id"]))


@lru_cache(maxsize=1)
def load_fips_dataset() -> dict:
    f = _PACKS_DIR / "fips-cmvp.json"
    return json.loads(f.read_text(encoding="utf-8"))


def pack_hashes() -> dict:
    """CRLF-normalized SHA-256 of every pack + the FIPS dataset (provenance)."""
    out = {}
    for p in sorted(_PACKS_DIR.glob("*")):
        if p.name == "PROVENANCE.json":
            continue
        data = p.read_bytes().replace(b"\r\n", b"\n")
        out[p.name] = hashlib.sha256(data).hexdigest()
    return dict(sorted(out.items()))


def load_provenance() -> dict | None:
    f = _PACKS_DIR / "PROVENANCE.json"
    if not f.is_file():
        return None
    return json.loads(f.read_text(encoding="utf-8"))


def fips_snapshot_date() -> str:
    return load_fips_dataset().get("snapshot_date", "")


# --- fact extraction -------------------------------------------------------

def _named_group(name: str | None) -> NamedGroup | None:
    if not name:
        return None
    low = name.lower()
    for g in NamedGroup:
        if g.name.lower() == low:
            return g
    return None


def _facts(result, fips_module: str | None) -> dict:
    f: dict = {
        "reachable": result.reachable,
        "tls_version": result.negotiated_version,
        "tls13": result.is_tls13,
        "version_below_13": result.version_below_13,
        "kex_group": result.group.negotiated_group,
        "kex_iana_recommended": result.group.iana_recommended,
        "downgrade_verdict": result.downgrade.verdict.value if result.downgrade else None,
        "downgrade_strippable": result.downgrade.strippable if result.downgrade else None,
        "hybrid_verdict": result.hybrid.verdict.value if result.hybrid else None,
        "fips_module": fips_module,
    }
    ng = _named_group(result.group.negotiated_group)
    if result.reachable and result.is_tls13:
        if ng is not None:
            f["kex_kind"] = ng.kind.value
            if ng.is_hybrid_pqc:
                f["kex_ml_kem"] = ng.ml_kem_param
                f["kex_nist_category"] = ng.nist_category
            else:  # observed-absent (classical/draft) -> definite, not unknown
                f["kex_ml_kem"] = "none"
                f["kex_nist_category"] = 0
        else:
            f["kex_kind"] = "unknown"
            f["kex_ml_kem"] = None
            f["kex_nist_category"] = None
    else:
        f["kex_kind"] = None
        f["kex_ml_kem"] = None
        f["kex_nist_category"] = None

    cipher_name = (result.completed_handshake.negotiated_cipher
                   if result.completed_handshake else None)
    cs = None
    if cipher_name:
        try:
            cs = CipherSuite[cipher_name]
        except KeyError:
            cs = None
    if cs is not None:
        bulk, bits, hsh, hbits = CIPHER_SUITE_FACTS[cs]
        f["bulk_cipher"], f["bulk_bits"], f["hash"], f["hash_bits"] = bulk, bits, hsh, hbits
    else:
        f["bulk_cipher"] = f["bulk_bits"] = f["hash"] = f["hash_bits"] = None

    if result.cert:
        f["sig_class"] = result.cert.sig_class.value
        f["sig_canonical"] = result.cert.sig_canonical or result.cert.sig_algo
        f["cert_signature"] = result.cert.sig_algo
        f["cert_key_algo"] = result.cert.key_algo
    else:
        f["sig_class"] = f["sig_canonical"] = f["cert_signature"] = f["cert_key_algo"] = None
    return f


# --- predicate evaluation (tri-state) --------------------------------------

def _leaf(node: dict, facts: dict) -> str:
    fact = node["fact"]
    v = facts.get(fact)
    if "present" in node:
        return _T if v is not None else _F
    if "absent" in node:
        return _T if v is None else _F
    if "is_true" in node:
        return _U if v is None else (_T if bool(v) is True else _F)
    if "is_false" in node:
        return _U if v is None else (_T if bool(v) is False else _F)
    if v is None:
        return _U
    if "equals" in node:
        return _T if v == node["equals"] else _F
    if "not_equals" in node:
        return _T if v != node["not_equals"] else _F
    if "in" in node:
        return _T if v in node["in"] else _F
    if "not_in" in node:
        return _T if v not in node["not_in"] else _F
    if "contains" in node:
        return _T if (isinstance(v, str) and node["contains"] in v) else _F
    if "not_contains" in node:
        return _T if (isinstance(v, str) and node["not_contains"] not in v) else _F
    if "gte" in node:
        try:
            return _T if v >= node["gte"] else _F
        except TypeError:
            return _U
    if "lte" in node:
        try:
            return _T if v <= node["lte"] else _F
        except TypeError:
            return _U
    raise ValueError(f"unknown predicate op: {node}")


def _eval(node: dict, facts: dict) -> str:
    if "all" in node:
        rs = [_eval(n, facts) for n in node["all"]]
        if _F in rs:
            return _F
        return _U if _U in rs else _T
    if "any" in node:
        rs = [_eval(n, facts) for n in node["any"]]
        if _T in rs:
            return _T
        return _U if _U in rs else _F
    if "not" in node:
        return {_T: _F, _F: _T, _U: _U}[_eval(node["not"], facts)]
    return _leaf(node, facts)


# --- rule evaluation -------------------------------------------------------

def _fmt_observed(fact_name: str | None, facts: dict) -> str:
    if not fact_name:
        return ""
    v = facts.get(fact_name)
    return "(not observed)" if v is None else str(v)


def _eval_fips(module: str | None, run_date: date, dataset: dict, rule: dict):
    if not module:
        return (ConformanceVerdict.UNKNOWN, Severity.LOW,
                rule.get("unknown_detail",
                         "no validated module is observable over TLS"))
    entry = _fips_lookup(module, dataset)
    if entry is None:
        return (ConformanceVerdict.UNKNOWN, Severity.LOW,
                f"module '{module}' is not in the bundled CMVP subset "
                f"(snapshot {dataset.get('snapshot_date')})")
    std = entry.get("standard")
    status = entry.get("status")
    cert = entry.get("cert") or "n/a"
    if std == "FIPS 140-3":
        return (ConformanceVerdict.PASS, Severity.INFO,
                f"{entry['name']} is FIPS 140-3 validated (cert {cert})")
    # FIPS 140-2
    historical = (status == "Historical") or (run_date >= _FIPS_140_2_HISTORICAL)
    if historical:
        return (ConformanceVerdict.FAIL, Severity[rule.get("severity", "HIGH")],
                f"{entry['name']} is FIPS 140-2 ({status}); on/after "
                f"{_FIPS_140_2_HISTORICAL.isoformat()} it is on the CMVP Historical "
                f"list and should not be included in new federal procurements")
    return (ConformanceVerdict.WARN, Severity.MEDIUM,
            f"{entry['name']} is FIPS 140-2 (cert {cert}); moves to the CMVP "
            f"Historical list on {_FIPS_140_2_HISTORICAL.isoformat()} — should not "
            f"be used in new procurements thereafter")


def _fips_lookup(module: str, dataset: dict) -> dict | None:
    m = module.strip().lower()
    for entry in dataset.get("modules", []):
        names = [entry["name"].lower()] + [a.lower() for a in entry.get("aliases", [])]
        if any(m == n or n in m or m in n for n in names):
            return entry
    return None


def _eval_rule(pack: dict, rule: dict, facts: dict, run_date: date,
               fips_dataset: dict) -> ConformanceFinding:
    finding = ConformanceFinding(
        pack=pack["id"], pack_title=pack["title"], profile=pack["profile"],
        rule_id=rule["id"], requirement=rule["requirement"],
        verdict=ConformanceVerdict.UNKNOWN,
        severity=Severity[rule.get("severity", "MEDIUM")],
        observed=_fmt_observed(rule.get("observed"), facts),
        mandate=rule.get("mandate", pack.get("mandate", "")),
        deadline=rule.get("deadline"),
        citation=rule.get("citation", pack.get("default_citation")),
    )
    if rule.get("check") == "fips_module":
        verdict, sev, detail = _eval_fips(facts.get("fips_module"), run_date,
                                          fips_dataset, rule)
        finding.verdict, finding.severity, finding.detail = verdict, sev, detail
        return finding

    when = rule.get("when")
    gate = _eval(when, facts) if when else _T
    if gate == _F:
        finding.verdict = ConformanceVerdict.NOT_APPLICABLE
        finding.severity = Severity.INFO
        finding.detail = rule.get("na_detail",
                                  "requirement does not apply to this observation")
        return finding
    if gate == _U:
        finding.verdict = ConformanceVerdict.UNKNOWN
        finding.severity = Severity.LOW
        finding.detail = "applicability could not be determined from observation"
        return finding

    res = _eval(rule["assert"], facts)
    if res == _T:
        finding.verdict = ConformanceVerdict.PASS
        finding.severity = Severity.INFO
        finding.detail = rule.get("pass_detail", "requirement satisfied")
    elif res == _F:
        fail_verdict = rule.get("fail_verdict", "FAIL")
        finding.verdict = ConformanceVerdict(fail_verdict)
        finding.severity = Severity[rule.get("severity", "MEDIUM")]
        finding.detail = rule.get("fail_detail", "requirement not satisfied")
    else:
        finding.verdict = ConformanceVerdict.UNKNOWN
        finding.severity = Severity.LOW
        finding.detail = rule.get("unknown_detail",
                                  "could not verify from observed artifacts")
    return finding


def _select_packs(profile: str) -> list[dict]:
    sel = _PROFILE_SELECT.get(profile, _PROFILE_SELECT["both"])
    return [p for p in load_packs() if p.get("profile") in sel]


def evaluate(result, *, profile: str = "both", run_date: date | None = None,
             fips_module: str | None = None) -> list[ConformanceFinding]:
    """Evaluate the selected packs against a ProbeResult; sets result.conformance."""
    if run_date is None:
        run_date = datetime.now(timezone.utc).date()
    facts = _facts(result, fips_module)
    fips_dataset = load_fips_dataset()
    findings: list[ConformanceFinding] = []
    for pack in _select_packs(profile):
        for rule in pack.get("rules", []):
            findings.append(_eval_rule(pack, rule, facts, run_date, fips_dataset))
    result.conformance = findings
    return findings


# --- policy CLI ------------------------------------------------------------

def run_policy_cli(args) -> int:
    from . import log
    action = args.action
    if action == "list":
        return _policy_list(args)
    if action == "show":
        return _policy_show(args)
    if action == "verify":
        return _policy_verify(args)
    log.warn(f"unknown policy action: {action}")
    return 1


def _policy_list(args) -> int:
    packs = load_packs()
    if args.format == "json":
        out = [{"id": p["id"], "title": p["title"], "profile": p["profile"],
                "status": p.get("status"), "mandate": p.get("mandate"),
                "rules": len(p.get("rules", []))} for p in packs]
        print(json.dumps(out, indent=2))
        return 0
    print("GreyNOC CryptoProbe — conformance packs\n")
    for p in packs:
        print(f"  {p['id']:<16} [{p['profile']:<8} {p.get('status','')}] "
              f"{len(p.get('rules', [])):>2} rules  — {p['title']}")
    ds = load_fips_dataset()
    print(f"\n  FIPS/CMVP dataset snapshot: {ds.get('snapshot_date')} "
          f"({len(ds.get('modules', []))} modules)")
    return 0


def _policy_show(args) -> int:
    from . import log
    if not args.pack:
        log.warn("usage: cryptoprobe policy show <pack-id>")
        return 1
    packs = {p["id"]: p for p in load_packs()}
    pack = packs.get(args.pack)
    if pack is None:
        log.warn(f"no such pack '{args.pack}'. Available: {', '.join(packs)}")
        return 1
    if args.format == "json":
        show = {k: v for k, v in pack.items() if k != "_file"}
        print(json.dumps(show, indent=2))
        return 0
    print(f"# {pack['title']}")
    print(f"id: {pack['id']}  profile: {pack['profile']}  status: {pack.get('status')}")
    print(f"mandate: {pack.get('mandate')}")
    print(f"citation: {pack.get('default_citation')}")
    if pack.get("summary"):
        print("\n" + " ".join(pack["summary"].split()))
    if pack.get("deadlines"):
        print("\ndeadlines:")
        for k, v in pack["deadlines"].items():
            print(f"  - {k}: {v}")
    print("\nrules:")
    for r in pack.get("rules", []):
        sev = r.get("severity", "MEDIUM")
        fv = r.get("fail_verdict", "FAIL")
        print(f"  [{r['id']}] ({sev}/{fv}) {r['requirement']}")
        if r.get("deadline"):
            print(f"      deadline: {r['deadline']}  mandate: {r.get('mandate', pack.get('mandate'))}")
    return 0


def _policy_verify(args) -> int:
    from . import log
    computed = pack_hashes()
    prov = load_provenance()
    if prov is None:
        log.warn("packs/PROVENANCE.json is missing")
        if args.format == "json":
            print(json.dumps({"ok": False, "reason": "PROVENANCE.json missing",
                              "computed": computed}, indent=2))
        return 1
    recorded = prov.get("hashes", {})
    mismatches = []
    for name, h in computed.items():
        if recorded.get(name) != h:
            mismatches.append(name)
    missing = [n for n in recorded if n not in computed]
    ok = not mismatches and not missing
    if args.format == "json":
        print(json.dumps({"ok": ok, "mismatches": mismatches, "missing": missing,
                          "snapshot_date": prov.get("fips_snapshot_date"),
                          "generated": prov.get("generated")}, indent=2))
    else:
        if ok:
            print(f"[+] policy packs verified: {len(computed)} files match "
                  f"PROVENANCE.json (generated {prov.get('generated')})")
        else:
            for n in mismatches:
                print(f"[!] hash mismatch: {n}")
            for n in missing:
                print(f"[!] recorded but missing: {n}")
    return 0 if ok else 2
