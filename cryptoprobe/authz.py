"""
GreyNOC CryptoProbe — authorization & scope gate.

CryptoProbe performs ACTIVE probing (it completes real handshakes against the
target), so unlike CryptoScan's passive code scan it MUST refuse to run without
explicit authorization. This is a non-negotiable GreyNOC operating standard.

Authorization is granted by either:
  * ``--i-have-authorization OP-TICKET`` — a free-form operator/ticket identifier
    that is recorded verbatim in the run manifest; or
  * ``--scope scope.yaml`` — a scope file naming the operator, ticket, the
    authorized targets, and an optional rate limit. The file's SHA-256 is
    recorded in the manifest for provenance.

When a scope file is present, every probed target must match an entry in it or
the probe is refused. The flag alone authorizes any target the operator points
at (the operator asserts authorization and is named in the manifest).

Nothing here trusts the network — it only governs whether we are allowed to
touch it.
"""

from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover - dependency declared in pyproject
    yaml = None


class AuthorizationError(Exception):
    """Raised when active probing is requested without valid authorization."""


@dataclass
class Scope:
    operator: str | None = None
    ticket: str | None = None
    rate_limit: float | None = None
    targets: list[str] = field(default_factory=list)
    notes: str = ""
    path: str | None = None
    sha256: str | None = None

    @property
    def identifier(self) -> str | None:
        if self.operator and self.ticket:
            return f"{self.operator}/{self.ticket}"
        return self.ticket or self.operator


@dataclass
class Authorization:
    """The resolved authorization for a run; embedded in the run manifest."""
    granted: bool
    identifier: str | None = None        # operator/ticket string, recorded verbatim
    source: str | None = None            # "flag" | "scope" | "flag+scope" | None
    scope: Scope | None = None
    reason: str = ""

    def to_dict(self) -> dict:
        d = {
            "granted": self.granted,
            "identifier": self.identifier,
            "source": self.source,
            "reason": self.reason,
        }
        if self.scope is not None:
            d["scope"] = {
                "path": self.scope.path,
                "sha256": self.scope.sha256,
                "operator": self.scope.operator,
                "ticket": self.scope.ticket,
                "rate_limit": self.scope.rate_limit,
                "target_count": len(self.scope.targets),
            }
        return d


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_scope(path: str) -> Scope:
    p = Path(path)
    if not p.is_file():
        raise AuthorizationError(f"scope file not found: {path}")
    if yaml is None:
        raise AuthorizationError(
            "PyYAML is required to read a scope file; install greynoc-cryptoprobe "
            "with its dependencies")
    raw = p.read_text(encoding="utf-8")
    try:
        doc = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise AuthorizationError(f"scope file is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise AuthorizationError("scope file must be a YAML mapping")
    auth = doc.get("authorization") or {}
    targets = doc.get("targets") or []
    if not isinstance(targets, list):
        raise AuthorizationError("scope 'targets' must be a list")
    scope = Scope(
        operator=_str_or_none(auth.get("operator")),
        ticket=_str_or_none(auth.get("ticket")),
        rate_limit=_float_or_none(auth.get("rate_limit")),
        targets=[str(t).strip() for t in targets if str(t).strip()],
        notes=str(doc.get("notes") or ""),
        path=str(p),
        sha256=_sha256_file(p),
    )
    if not scope.identifier:
        raise AuthorizationError(
            "scope file must name an authorization.operator and/or "
            "authorization.ticket")
    if not scope.targets:
        raise AuthorizationError("scope file authorizes no targets")
    return scope


def resolve(flag_identifier: str | None, scope_path: str | None) -> Authorization:
    """Resolve authorization from the CLI inputs. Never raises; returns an
    Authorization whose ``granted`` is False when nothing authorizes the run."""
    scope = load_scope(scope_path) if scope_path else None
    flag = _str_or_none(flag_identifier)
    if scope is not None and flag is not None:
        return Authorization(True, identifier=flag, source="flag+scope",
                             scope=scope,
                             reason="operator flag recorded; targets gated by scope")
    if scope is not None:
        return Authorization(True, identifier=scope.identifier, source="scope",
                             scope=scope,
                             reason="authorized by scope file")
    if flag is not None:
        return Authorization(True, identifier=flag, source="flag",
                             reason="operator asserted authorization via flag")
    return Authorization(
        False,
        reason="no authorization: pass --i-have-authorization OP-TICKET or "
               "--scope scope.yaml to run active probes")


def target_in_scope(scope: Scope, host: str, port: int) -> bool:
    """Whether (host, port) matches any scope entry.

    Entry forms: ``host`` (any port), ``host:port`` (exact), ``*.glob`` (host
    glob, any port), CIDR like ``10.0.0.0/24`` (IP membership, any port).
    """
    host = host.strip().strip("[]").lower()
    for entry in scope.targets:
        e = entry.strip().lower()
        e_host, e_port = _split_entry(e)
        if e_port is not None and e_port != port:
            continue
        if _host_matches(e_host, host):
            return True
    return False


def authorize_target(auth: Authorization, host: str, port: int) -> tuple[bool, str]:
    """Decide whether a single target may be probed under this authorization."""
    if not auth.granted:
        return False, auth.reason
    if auth.scope is not None:
        if target_in_scope(auth.scope, host, port):
            return True, "in authorized scope"
        return False, (f"{host}:{port} is not in the authorized scope "
                       f"({auth.scope.path})")
    return True, "authorized by operator"


# --- helpers ---------------------------------------------------------------

def _split_entry(entry: str) -> tuple[str, int | None]:
    # IPv6 CIDR/literal in brackets, or host:port — only treat a trailing
    # ":digits" as a port (avoids splitting an IPv6 address).
    if entry.startswith("["):
        host, _, rest = entry[1:].partition("]")
        port = rest.lstrip(":")
        return host, (int(port) if port.isdigit() else None)
    host, sep, maybe_port = entry.rpartition(":")
    if sep and maybe_port.isdigit() and "/" not in maybe_port:
        return host, int(maybe_port)
    return entry, None


def _host_matches(entry_host: str, host: str) -> bool:
    if "/" in entry_host:  # CIDR
        try:
            net = ipaddress.ip_network(entry_host, strict=False)
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    if entry_host == host:
        return True
    if "*" in entry_host or "?" in entry_host:
        return fnmatch.fnmatch(host, entry_host)
    return False


def _str_or_none(v) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _float_or_none(v) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None
