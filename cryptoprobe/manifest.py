"""
GreyNOC CryptoProbe — run manifest (provenance).

The manifest is the signable record of a run. It captures everything an auditor
needs to reproduce and trust the verdicts, per the GreyNOC standard:
tool version + git commit, ruleset-pack hashes, FIPS-dataset snapshot date + hash,
target(s), UTC run timestamp, an environment fingerprint, the authorization
identifier, and the SHA-256 of every raw handshake transcript. It also binds to
the findings via a reproducible ``results_sha256`` (computed with the timestamp
excluded, so it is identical across runs over identical inputs).

``attest`` signs the canonical bytes of this manifest.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from pathlib import Path

from ._version import __version__


def _git_commit() -> str | None:
    """Best-effort git commit of the running tree; None when not in a repo."""
    here = Path(__file__).resolve().parent
    try:
        out = subprocess.run(
            ["git", "-C", str(here), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=False)
        commit = out.stdout.decode("ascii", "replace").strip()
        return commit or None
    except (OSError, subprocess.SubprocessError):
        return None


def _environment(run_meta: dict) -> dict:
    osv = platform.platform()
    pyv = platform.python_version()
    arch = platform.machine()
    openssl = (run_meta.get("openssl", {}) or {}).get("version")
    fp_src = f"{osv}|{pyv}|{arch}|{openssl}"
    return {
        "os": osv,
        "python": pyv,
        "architecture": arch,
        "openssl": openssl,
        "fingerprint_sha256": hashlib.sha256(fp_src.encode()).hexdigest(),
    }


def _all_transcripts(results) -> list[dict]:
    out = []
    for r in results:
        for d in r.transcript_digests():
            out.append({"target": r.target, **d})
    return sorted(out, key=lambda d: (d["target"], d["method"], d["sha256"]))


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def results_digest(doc: dict) -> str:
    """Reproducible digest of the findings — excludes the run timestamp."""
    payload = {"summary": doc.get("summary"), "targets": doc.get("targets")}
    return hashlib.sha256(_canonical(payload)).hexdigest()


def build(doc: dict, results, args) -> dict:
    """Build the run manifest from the already-built result document."""
    run = dict(doc.get("run", {}))
    run["git_commit"] = _git_commit()
    run["environment"] = _environment(run)
    run["results_sha256"] = results_digest(doc)
    return {
        "manifest_version": "1.0",
        "manifest_type": "greynoc-cryptoprobe-run",
        "tool": run.get("tool", {"name": "GreyNOC CryptoProbe", "version": __version__}),
        "run": run,
        "summary": doc.get("summary", {}),
        "targets": [t.get("target") for t in doc.get("targets", [])],
        "transcripts": _all_transcripts(results),
        "results": doc.get("targets", []),
    }


def canonical_bytes(manifest: dict) -> bytes:
    """Bytes that an attestation signs. Stable for identical manifests."""
    return _canonical(manifest)


def manifest_sha256(manifest: dict) -> str:
    return hashlib.sha256(canonical_bytes(manifest)).hexdigest()
