# Changelog

Format loosely follows [Keep a Changelog](https://keepachangelog.com/). Mandate
dates cited in the conformance packs are verified against primary sources; see
`cryptoprobe/packs/PROVENANCE.json`.

## [0.1.0] — active PQC migration validation (initial release)

### Added
- **TLS endpoint validation** — completes real TLS 1.3 handshakes and records
  the transcript; classifies negotiated version, key-exchange group (CNSA-grade
  hybrid / deprecated draft / classical), and the certificate signature chain.
- **Downgrade / HNDL-resistance probing** — a controlled matrix of handshakes
  (PQC-only, hybrid+classical, classical-only) yields a downgrade-resistance
  verdict: can a network attacker strip PQC and force classical key
  establishment? Confirms hybrid correctness (both ECDHE and ML-KEM shares).
- **Declarative conformance engine** with bundled, provenance-hashed packs:
  CNSA 2.0 (NSS), OMB M-26-15 (federal civilian), FIPS 140-3 module status, and
  a NIST IR 8547 deprecation-runway reference tier. `--profile nss|civilian`
  selects a pack; absent a selector both are evaluated and labeled (the
  NSS-vs-civilian SLH-DSA divergence is surfaced explicitly).
- **CBOM ingest / enrich / emit** — ingests a CryptoScan CycloneDX 1.6 CBOM and
  emits an enriched one, carrying active-verification results end to end.
- **Signed, reproducible attestation** — a provenance-tracked run manifest
  signed with ML-DSA-87 by default (Ed25519 fallback), operator-supplied keys.
- **Outputs**: human report, machine JSON, SARIF 2.1.0, enriched CBOM —
  deterministic and sorted (byte-identical across runs modulo the run timestamp).
- **IKEv2/IPsec capability detection** (RFC 9370 / 9242 signals) reported with an
  honest `NOT_YET_VALIDATED` status and a v0.2 roadmap note.
- **Authorization gate** — active probing is refused without a recorded operator
  /ticket (`--i-have-authorization`) or an authorizing `--scope` file; rate
  limited by default.
- `selftest` against known-good public PQC endpoints; offline self-checks.

### Notes
- Stack: Python (sibling of CryptoScan). Completed PQC handshakes use the
  system `openssl` (>= 3.5) when present; the dependency-free raw-socket probe
  drives the downgrade matrix and group classification everywhere else.
- Authorized testing only. Handshake negotiation + certificate inspection only —
  no exploitation, no DoS, no auth attacks.
