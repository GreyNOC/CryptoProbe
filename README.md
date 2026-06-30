# GreyNOC CryptoProbe

**Active PQC migration validator & signed attestation.** `GN-SEC-CRYPTOPROBE-001`

CryptoProbe is the active-verification counterpart to
[GreyNOC CryptoScan](https://github.com/GreyNOC/Crypto-Scan). CryptoScan answers
*"what crypto do I have and what is the quantum risk?"* (passive inventory →
CycloneDX 1.6 CBOM). CryptoProbe answers *"did the PQC migration actually hold,
is it conformant, is it downgrade-resistant, and can I prove it?"* — by
completing **real** TLS handshakes, probing **downgrade resistance**, evaluating
**declarative conformance packs**, and emitting a **signed, reproducible
attestation**.

> ⚠️ **AUTHORIZED TESTING ONLY.** CryptoProbe actively connects to the targets
> you point it at and completes TLS handshakes with them. It refuses to run
> without a recorded authorization (`--i-have-authorization OP-TICKET`) or an
> authorizing `--scope` file, and rate-limits by default. It performs handshake
> negotiation and certificate inspection **only** — no exploitation, no
> denial-of-service, no authentication attacks. You are solely responsible for
> having permission to probe any target.

## Why it is different

Commercial tools and open libraries are weak on four axes; CryptoProbe leads on
each:

1. **Active verification, not claims** — we complete PQC/hybrid handshakes and
   inspect the negotiated result. We never trust advertised capability.
2. **Adversarial downgrade testing** — we probe whether an attacker can strip
   PQC and force classical key establishment (the harvest-now-decrypt-later
   exposure call). This is GreyNOC's offensive-security edge.
3. **Reproducible, signed attestation** — every run emits a deterministic,
   provenance-tracked, ML-DSA-87-signed attestation. No fabrication, ever.
4. **Mandate-aware verdicts** — every finding is tied to the specific U.S.
   deadline that makes it actionable, and the NSS-vs-civilian divergence is
   handled cleanly.

## The pipeline

```
  CryptoScan                migrate                 CryptoProbe
  (discover)        ───────────────────────►        (verify + attest)
      │                                                   │
  scan.cbom.json  ──────────────────────────────►  --cbom-in
  (CycloneDX 1.6)                                        │
                                                   ┌──────┴───────┐
                                                   │ probe + verify │
                                                   └──────┬───────┘
                                                          ▼
                            probe.cbom.json  +  run.json  +  attestation.json
                            (enriched CBOM)  (manifest)   (ML-DSA-87 signed)
```

## Stack decision & rationale

**Python.** CryptoScan is Python (`cryptography`-based, argparse CLI, CycloneDX
1.6 emitter), and CryptoProbe must be its sibling — share its CBOM pipeline,
`Finding`/`Severity` vocabulary, CLI idioms, exit-code conventions and packaging.
Going greenfield in Go would fork the CBOM model and the field-operator workflow
for no benefit here.

Completing **real** PQC/hybrid handshakes is capability-tiered and honest:

- The **raw-socket ClientHello probe** (adapted from CryptoScan's `tls13_probe`)
  is dependency-free and deterministic, and — crucially — lets us control the
  *offered* group set. It drives the downgrade matrix and group classification
  everywhere, including air-gapped / Termux.
- The **completed-handshake verifier** shells out to the system `openssl`
  (≥ 3.5, which negotiates `X25519MLKEM768` and the ML-KEM hybrids natively) to
  actually finish the cryptographic key exchange and read the negotiated group
  from a real, completed handshake. When `openssl` is absent or too old, that
  evidence is reported `UNKNOWN` with the reason — never guessed.

Python's stdlib `ssl` is typically linked against an OpenSSL without PQC groups
and does not expose the negotiated TLS 1.3 group at all, which is exactly why
both mechanisms above exist.

## Mandate / deadline reference

Every date below is verified against a primary source (see
`cryptoprobe/packs/*.yaml` for per-rule citations and `PROVENANCE.json`).

| Mandate | Scope | Key requirement | Deadline(s) |
|---|---|---|---|
| **EO 14306** | Federal (NSS via NSA, non-NSS via OMB) | Support TLS 1.3 or a successor | **2030-01-02** ("not later than") |
| **CNSA 2.0** | National Security Systems | ML-KEM-1024, ML-DSA-87, AES-256, SHA-384/512; **SLH-DSA not approved** | New acquisitions **2027-01-01**; exclusive use 2030 (signing/networking) / 2033 (web, cloud, OS); full 2035 |
| **OMB M-26-15** | Federal civilian (excludes NSS) | ML-KEM, ML-DSA, **SLH-DSA permitted** (hash-based fallback) | Prioritized migration **2030-12-31**; phased through 2035 |
| **FIPS 140-3** | Federal modules | FIPS 140-2 modules → CMVP **Historical** list; *should not be included in new procurements* (not auto-revoked) | **2026-09-21** |
| **NIST IR 8547** *(draft)* | General enterprise tier | Classical asymmetric (RSA/ECDSA/ECDH/DH/EdDSA) runway, keyed to strength | 112-bit: deprecated 2030 / disallowed 2035; ≥128-bit: disallowed 2035 |

The **NSS-vs-civilian SLH-DSA divergence** is a first-class feature: the same
SLH-DSA observation is conformant under `--profile civilian` (M-26-15 Appendix A)
but non-conformant under `--profile nss` (CNSA 2.0 excludes it).

## Install

```bash
pip install -e ".[validation]"     # validation extra adds CBOM schema checking
```

Requires Python ≥ 3.10. For completed-handshake verification, a system
`openssl` ≥ 3.5 on `PATH` (otherwise that evidence is reported `UNKNOWN`).

## Usage

```bash
# Validate a single endpoint (authorization required for active probing)
cryptoprobe scan pq.cloudflareresearch.com:443 --i-have-authorization OP-1234

# Many targets, ingest a CryptoScan CBOM, emit the enriched CBOM + run manifest
cryptoprobe scan --targets targets.txt --scope scope.yaml \
  --cbom-in scan.cbom.json --cbom-out probe.cbom.json --run-out run.json

# Sign the run with ML-DSA-87 (operator-supplied key)
cryptoprobe attest --run run.json --sign-key ml-dsa.key --out attestation.json
cryptoprobe attest --verify attestation.json --pub-key ml-dsa.pub

# Inspect / validate the conformance packs
cryptoprobe policy list
cryptoprobe policy show cnsa-2.0
cryptoprobe policy verify

# Validate the toolchain against known-good public PQC endpoints
cryptoprobe selftest
```

## Outputs

- **Human report** — severity-ranked findings, downgrade verdict, conformance.
- **Machine JSON** (`--json`) — findings + verdicts.
- **SARIF 2.1.0** (`--sarif`) — for CI / code-scanning.
- **Enriched CBOM** (`--cbom-out`) — CycloneDX 1.6, round-trips with CryptoScan.
- **Run manifest** (`--run-out`) + **signed attestation** (`attest`).

All deterministic and sorted: two runs over identical inputs produce
byte-identical output except the explicit run timestamp.

## Exit codes

`0` ok · `2` verdicts at/above `--fail-on` (gate CI) · `3` active probe refused
(no authorization) · `1` usage/runtime error.

## Scope & limitations (v0.1.0)

- TLS 1.3 endpoint validation + downgrade matrix is the primary, complete
  surface. TLS 1.2-and-below is detected and flagged (EO 14306) but PQC groups
  are a TLS 1.3 feature.
- IKEv2/IPsec is **capability detection only** (`NOT_YET_VALIDATED`); full
  validation is flagged for v0.2.
- Completed-handshake evidence requires `openssl` ≥ 3.5; otherwise reported
  `UNKNOWN`.

## Development

```bash
pip install -e ".[validation]"
pip install pytest ruff
python -m pytest -q tests/      # unit + golden-file (no network)
ruff check cryptoprobe
```

See [CHANGELOG.md](CHANGELOG.md). Proprietary — GreyNOC. Authorized testing only.
