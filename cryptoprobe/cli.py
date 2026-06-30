"""
GreyNOC CryptoProbe — command-line interface.

  cryptoprobe scan    <host[:port]> [...] [--profile nss|civilian|both]
                      [--i-have-authorization OP-TICKET | --scope scope.yaml]
                      [--cbom-in scan.cbom.json] [--cbom-out probe.cbom.json]
                      [--run-out run.json] [--format human|json|sarif]
  cryptoprobe attest  --run run.json --sign-key ml-dsa.key --out attestation.json
  cryptoprobe attest  --verify attestation.json
  cryptoprobe policy  list | show <pack> | verify
  cryptoprobe selftest

CryptoProbe performs ACTIVE probing; ``scan`` refuses to run without an explicit
authorization (``--i-have-authorization`` or ``--scope``). Exit codes mirror
CryptoScan: 0 ok, 2 when verdicts at/above ``--fail-on`` are present (CI gate),
3 when authorization is refused, 1 on usage/runtime error.
"""

from __future__ import annotations

import argparse

from . import __version__
from . import log

# Exit codes (sane, per verdict severity / operating standard).
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2       # verdicts at/above --fail-on present (gate CI)
EXIT_UNAUTHORIZED = 3   # active probe refused for lack of authorization

_GATE_CHOICES = ["critical", "high", "medium", "low", "none"]


def _add_global(parent: argparse.ArgumentParser) -> None:
    parent.add_argument("-v", "--verbose", action="count", default=0,
                        help="-v debug, -vv trace (to stderr)")
    parent.add_argument("--scope", metavar="FILE",
                        help="authorization scope file (YAML); gates targets")
    parent.add_argument("--timeout", type=float, default=8.0, metavar="SEC",
                        help="per-handshake timeout (default: 8.0)")
    parent.add_argument("--rate-limit", type=float, default=1.0, metavar="PER_SEC",
                        help="max handshakes/sec per run (default: 1.0)")
    parent.add_argument("--format", choices=["human", "json", "sarif"],
                        default="human",
                        help="primary stdout format (default: human)")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="cryptoprobe",
        description="GreyNOC CryptoProbe — active PQC migration validator & "
                    "signed attestation")
    p.add_argument("--version", action="version",
                   version=f"GreyNOC CryptoProbe {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # --- scan ---------------------------------------------------------------
    sp_scan = sub.add_parser("scan", help="actively validate TLS target(s)")
    _add_global(sp_scan)
    sp_scan.add_argument("targets", nargs="*", metavar="HOST[:PORT]",
                         help="one or more targets")
    sp_scan.add_argument("--target", action="append", default=[], metavar="HOST[:PORT]",
                         help="add a target (repeatable)")
    sp_scan.add_argument("--targets", dest="targets_file", metavar="FILE",
                         help="read targets from a file (one host[:port] per line)")
    sp_scan.add_argument("--i-have-authorization", dest="authorization",
                         metavar="OP-TICKET",
                         help="operator/ticket id asserting authorization "
                              "(recorded in the manifest)")
    sp_scan.add_argument("--profile", choices=["nss", "civilian", "both"],
                         default="both",
                         help="conformance profile (default: both, labeled)")
    sp_scan.add_argument("--cbom-in", metavar="FILE",
                         help="ingest a CryptoScan CycloneDX 1.6 CBOM as expectations")
    sp_scan.add_argument("--cbom-out", metavar="FILE",
                         help="write the enriched CycloneDX 1.6 CBOM")
    sp_scan.add_argument("--run-out", metavar="FILE",
                         help="write the run manifest JSON (signable with `attest`)")
    sp_scan.add_argument("--report", metavar="FILE", help="write the human report")
    sp_scan.add_argument("--json", dest="json_out", metavar="FILE",
                         help="write machine findings JSON")
    sp_scan.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0")
    sp_scan.add_argument("--no-downgrade", action="store_true",
                         help="skip the downgrade-resistance probe matrix")
    sp_scan.add_argument("--no-completed-handshake", action="store_true",
                         help="skip the openssl completed-handshake verification")
    sp_scan.add_argument("--fail-on", choices=_GATE_CHOICES, default="high",
                         metavar="{critical,high,medium,low,none}",
                         help="severity that makes the scan exit 2 (default: high)")

    # --- attest -------------------------------------------------------------
    sp_att = sub.add_parser("attest", help="sign / verify a run attestation")
    sp_att.add_argument("-v", "--verbose", action="count", default=0)
    sp_att.add_argument("--run", metavar="FILE", help="run manifest to attest")
    sp_att.add_argument("--sign-key", metavar="FILE",
                        help="operator-supplied signing key (PEM)")
    sp_att.add_argument("--signer", choices=["ml-dsa-87", "ed25519"],
                        default="ml-dsa-87",
                        help="signature algorithm (default: ml-dsa-87)")
    sp_att.add_argument("--out", metavar="FILE", help="write the signed attestation")
    sp_att.add_argument("--verify", metavar="ATTESTATION",
                        help="verify an existing attestation instead of signing")
    sp_att.add_argument("--pub-key", metavar="FILE",
                        help="public key for --verify (PEM)")

    # --- policy -------------------------------------------------------------
    sp_pol = sub.add_parser("policy", help="inspect / validate ruleset packs")
    sp_pol.add_argument("-v", "--verbose", action="count", default=0)
    sp_pol.add_argument("action", choices=["list", "show", "verify"])
    sp_pol.add_argument("pack", nargs="?", help="pack id for `show` (e.g. cnsa-2.0)")
    sp_pol.add_argument("--format", choices=["human", "json"], default="human")

    # --- selftest -----------------------------------------------------------
    sp_self = sub.add_parser(
        "selftest", help="validate against known-good PQC endpoints (network)")
    sp_self.add_argument("-v", "--verbose", action="count", default=0)
    sp_self.add_argument("--timeout", type=float, default=10.0, metavar="SEC")
    sp_self.add_argument("--offline", action="store_true",
                         help="run only the offline self-checks (no network)")

    args = p.parse_args(argv)
    log.set_verbosity(getattr(args, "verbose", 0))
    log.force_utf8()

    try:
        if args.cmd == "scan":
            return _cmd_scan(args)
        if args.cmd == "attest":
            return _cmd_attest(args)
        if args.cmd == "policy":
            return _cmd_policy(args)
        if args.cmd == "selftest":
            return _cmd_selftest(args)
    except KeyboardInterrupt:
        log.warn("interrupted")
        return EXIT_ERROR
    return EXIT_ERROR


def _cmd_scan(args) -> int:
    from . import authz, targets as targets_mod

    # Resolve authorization first — refuse before touching the network.
    try:
        auth = authz.resolve(args.authorization, args.scope)
    except authz.AuthorizationError as exc:
        log.warn(str(exc))
        return EXIT_UNAUTHORIZED
    if not auth.granted:
        log.warn(auth.reason)
        log.warn("active probing refused. Re-run with "
                 "--i-have-authorization OP-TICKET or --scope scope.yaml.")
        return EXIT_UNAUTHORIZED

    # Collect targets.
    specs = list(args.targets) + list(args.target)
    tlist: list = []
    for s in specs:
        try:
            tlist.append(targets_mod.parse_target(s))
        except ValueError as exc:
            log.warn(f"skipping {exc}")
    if args.targets_file:
        try:
            tlist.extend(targets_mod.load_targets_file(args.targets_file))
        except (OSError, ValueError) as exc:
            log.warn(str(exc))
            return EXIT_ERROR
    tlist = targets_mod.sorted_unique(tlist)
    if not tlist and not args.cbom_in:
        log.warn("no targets given (pass HOST[:PORT], --target, or --targets FILE)")
        return EXIT_ERROR

    log.info(f"authorized: {auth.identifier} (source: {auth.source})")

    try:
        from . import engine
    except ImportError as exc:  # pragma: no cover - phase guard
        log.warn(f"probe engine not available yet: {exc}")
        log.info(f"would probe {len(tlist)} target(s): "
                 + ", ".join(str(t) for t in tlist))
        return EXIT_OK
    return engine.run_scan(args, auth, tlist)


def _cmd_attest(args) -> int:
    try:
        from . import attest
    except ImportError as exc:  # pragma: no cover - phase guard
        log.warn(f"attestation subsystem not available yet: {exc}")
        return EXIT_ERROR
    return attest.run_cli(args)


def _cmd_policy(args) -> int:
    try:
        from . import conformance
    except ImportError as exc:  # pragma: no cover - phase guard
        log.warn(f"conformance engine not available yet: {exc}")
        return EXIT_ERROR
    return conformance.run_policy_cli(args)


def _cmd_selftest(args) -> int:
    try:
        from . import selftest
    except ImportError as exc:  # pragma: no cover - phase guard
        log.warn(f"selftest not available yet: {exc}")
        return EXIT_ERROR
    return selftest.run(args)


if __name__ == "__main__":
    raise SystemExit(main())
