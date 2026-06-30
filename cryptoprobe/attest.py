"""
GreyNOC CryptoProbe — signed, reproducible attestation.

A PQC validator should sign its own attestations with PQC. We sign the canonical
bytes of the run manifest with ML-DSA-87 by default (via the system openssl >=
3.5), with Ed25519 as a fallback signer (via ``cryptography``). Signing keys are
ALWAYS operator-supplied — the tool never generates-and-forgets a key for a real
attestation (``generate_keypair`` exists only for selftest/tests).

The attestation embeds the manifest, the signer's public key, and the signature
over the canonicalized manifest, so a third party can verify it offline with the
operator's trusted public key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from . import log, manifest as manifest_mod, handshake
from ._version import __version__


class AttestError(Exception):
    pass


_ALG_DISPLAY = {"ml-dsa-87": "ML-DSA-87", "ed25519": "Ed25519"}


# --- ML-DSA-87 via openssl -------------------------------------------------

def _openssl() -> str:
    cap = handshake.capability()
    if not cap.available or not cap.path:
        raise AttestError("openssl is required for ML-DSA-87 signing and was not "
                          "found; use --signer ed25519 instead")
    if not cap.supports_ml_dsa:
        raise AttestError(f"openssl {cap.version} does not support ML-DSA; use "
                          f"--signer ed25519 instead")
    return cap.path


def _run(args: list[str], timeout: float = 30) -> subprocess.CompletedProcess:
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, check=False)


def _ml_dsa_sign(key_path: str, data: bytes) -> bytes:
    ossl = _openssl()
    with tempfile.TemporaryDirectory() as d:
        infile = Path(d) / "msg.bin"
        sigfile = Path(d) / "sig.bin"
        infile.write_bytes(data)
        p = _run([ossl, "pkeyutl", "-sign", "-inkey", key_path, "-rawin",
                  "-in", str(infile), "-out", str(sigfile)])
        if p.returncode != 0 or not sigfile.exists():
            raise AttestError(f"ML-DSA signing failed: "
                              f"{p.stderr.decode('utf-8', 'replace').strip()}")
        return sigfile.read_bytes()


def _ml_dsa_public_pem(key_path: str) -> bytes:
    ossl = _openssl()
    p = _run([ossl, "pkey", "-in", key_path, "-pubout"])
    if p.returncode != 0 or not p.stdout:
        raise AttestError("could not extract ML-DSA public key: "
                          f"{p.stderr.decode('utf-8', 'replace').strip()}")
    return p.stdout


def _ml_dsa_verify(pub_pem: bytes, data: bytes, sig: bytes) -> bool:
    ossl = _openssl()
    with tempfile.TemporaryDirectory() as d:
        pub = Path(d) / "pub.pem"
        infile = Path(d) / "msg.bin"
        sigfile = Path(d) / "sig.bin"
        pub.write_bytes(pub_pem)
        infile.write_bytes(data)
        sigfile.write_bytes(sig)
        p = _run([ossl, "pkeyutl", "-verify", "-pubin", "-inkey", str(pub),
                  "-rawin", "-in", str(infile), "-sigfile", str(sigfile)])
        out = (p.stdout + p.stderr).decode("utf-8", "replace").lower()
        return p.returncode == 0 and "success" in out


# --- Ed25519 via cryptography ----------------------------------------------

def _ed25519_sign(key_path: str, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(Path(key_path).read_bytes(), password=None)
    return key.sign(data)


def _ed25519_public_pem(key_path: str) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    key = load_pem_private_key(Path(key_path).read_bytes(), password=None)
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def _ed25519_verify(pub_pem: bytes, data: bytes, sig: bytes) -> bool:
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    from cryptography.exceptions import InvalidSignature
    try:
        pub = load_pem_public_key(pub_pem)
        pub.verify(sig, data)
        return True
    except (InvalidSignature, ValueError):
        return False


# --- keygen (selftest / tests only) ----------------------------------------

def generate_keypair(algorithm: str, priv_path: str) -> bytes:
    """Generate a signing keypair. For selftest/tests — real runs supply keys."""
    algorithm = algorithm.lower()
    if algorithm == "ml-dsa-87":
        ossl = _openssl()
        p = _run([ossl, "genpkey", "-algorithm", "ML-DSA-87", "-out", priv_path])
        if p.returncode != 0:
            raise AttestError(f"ML-DSA keygen failed: "
                              f"{p.stderr.decode('utf-8', 'replace').strip()}")
        return _ml_dsa_public_pem(priv_path)
    if algorithm == "ed25519":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        key = Ed25519PrivateKey.generate()
        Path(priv_path).write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        return key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
    raise AttestError(f"unknown signer algorithm: {algorithm}")


# --- sign / verify ---------------------------------------------------------

def sign(manifest: dict, key_path: str, signer: str = "ml-dsa-87") -> dict:
    signer = signer.lower()
    data = manifest_mod.canonical_bytes(manifest)
    if signer == "ml-dsa-87":
        sig = _ml_dsa_sign(key_path, data)
        pub_pem = _ml_dsa_public_pem(key_path)
    elif signer == "ed25519":
        sig = _ed25519_sign(key_path, data)
        pub_pem = _ed25519_public_pem(key_path)
    else:
        raise AttestError(f"unknown signer: {signer}")
    return {
        "attestation_version": "1.0",
        "attestation_type": "greynoc-cryptoprobe-attestation",
        "tool": {"name": "GreyNOC CryptoProbe", "version": __version__},
        "signing": {
            "algorithm": _ALG_DISPLAY[signer],
            "canonicalization": "json-sorted-compact-utf8",
            "hash": "sha256",
        },
        "manifest_sha256": hashlib.sha256(data).hexdigest(),
        "signature_b64": base64.b64encode(sig).decode("ascii"),
        "public_key_pem": pub_pem.decode("ascii"),
        "public_key_sha256": hashlib.sha256(pub_pem).hexdigest(),
        "manifest": manifest,
    }


def verify(attestation: dict, pub_key_path: str | None = None) -> tuple[bool, str, bool]:
    """Verify an attestation.

    Returns (ok, detail, authenticated). ``ok`` means the signature is
    cryptographically valid over the (hash-bound) manifest. ``authenticated`` is
    True ONLY when the operator supplied the trusted public key via ``pub_key_path``
    — a check against the attestation's own EMBEDDED key proves internal
    consistency, not authenticity (the embedded key is attacker-controllable), so
    it is never reported as authenticated.
    """
    manifest = attestation.get("manifest")
    if not isinstance(manifest, dict):
        return False, "attestation has no embedded manifest", False
    data = manifest_mod.canonical_bytes(manifest)
    digest = hashlib.sha256(data).hexdigest()
    if attestation.get("manifest_sha256") != digest:
        return False, "manifest hash mismatch — the manifest was altered after signing", False
    try:
        sig = base64.b64decode(attestation["signature_b64"])
    except (KeyError, ValueError):
        return False, "missing or malformed signature", False
    using_operator_key = bool(pub_key_path)
    if using_operator_key:
        pub_pem = Path(pub_key_path).read_bytes()
        src = f"operator key {pub_key_path}"
    else:
        pem = attestation.get("public_key_pem")
        if not pem:
            return False, "no public key supplied (--pub-key) and none embedded", False
        pub_pem = pem.encode("ascii")
        src = "embedded public key"
    alg = attestation.get("signing", {}).get("algorithm", "")
    try:
        if alg.upper().startswith("ML-DSA"):
            ok = _ml_dsa_verify(pub_pem, data, sig)
        elif alg.lower() == "ed25519":
            ok = _ed25519_verify(pub_pem, data, sig)
        else:
            return False, f"unknown signing algorithm: {alg}", False
    except AttestError as exc:
        return False, str(exc), False
    authenticated = ok and using_operator_key
    if not ok:
        return False, f"{alg} signature INVALID ({src})", False
    if authenticated:
        return True, f"{alg} signature valid ({src})", True
    return (True,
            f"{alg} signature is internally consistent but the signer is "
            f"UNAUTHENTICATED — verified against the attestation's own embedded "
            f"key, which is attacker-controllable. Supply --pub-key with the "
            f"operator's trusted public key to authenticate.",
            False)


# --- CLI -------------------------------------------------------------------

def run_cli(args) -> int:
    log.set_verbosity(getattr(args, "verbose", 0))
    if args.verify:
        return _cli_verify(args)
    return _cli_sign(args)


def _cli_sign(args) -> int:
    if not args.run:
        log.warn("usage: cryptoprobe attest --run run.json --sign-key KEY --out FILE")
        return 1
    if not args.sign_key:
        log.warn("a signing key is required (--sign-key); CryptoProbe never "
                 "auto-generates attestation keys")
        return 1
    try:
        manifest = json.loads(Path(args.run).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warn(f"could not read run manifest: {exc}")
        return 1
    try:
        att = sign(manifest, args.sign_key, args.signer)
    except AttestError as exc:
        log.warn(str(exc))
        return 1
    out = args.out or "attestation.json"
    log.write_text(out, json.dumps(att, indent=2))
    log.ok(f"attestation written: {out}")
    log.info(f"  signer: {att['signing']['algorithm']} "
             f"(pubkey sha256 {att['public_key_sha256'][:16]}…)")
    log.info(f"  manifest sha256: {att['manifest_sha256'][:16]}…")
    return 0


def _cli_verify(args) -> int:
    try:
        att = json.loads(Path(args.verify).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warn(f"could not read attestation: {exc}")
        return 1
    ok, detail, authenticated = verify(att, args.pub_key)
    if ok and authenticated:
        log.ok(detail)
        return 0
    if ok and not authenticated:
        # Self-consistent but not authenticated — must not read as a clean pass.
        log.warn(detail)
        return 2
    log.warn(detail)
    return 2
