"""
GreyNOC CryptoProbe — target parsing.

Mirrors CryptoScan's ``_parse_target`` (IPv6-bracket aware) and adds a targets
file loader (one ``host[:port]`` per line, ``#`` comments, blank lines ignored).
Targets are returned sorted+deduplicated so a run over a target file is
order-independent (a reproducibility requirement).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, order=True)
class Target:
    host: str
    port: int

    def __str__(self) -> str:
        if ":" in self.host and not self.host.startswith("["):
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"


def parse_target(spec: str, default_port: int = 443) -> Target:
    """Parse ``host``, ``host:port``, ``[ipv6]:port`` into a Target."""
    t = spec.strip()
    if not t:
        raise ValueError("empty target")
    if t.startswith("["):  # bracketed IPv6
        host, _, rest = t[1:].partition("]")
        port = rest.lstrip(":")
        if port and not port.isdigit():
            raise ValueError(f"bad target '{spec}': port must be numeric")
        return Target(host, int(port) if port else default_port)
    if ":" in t:
        host, _, port = t.rpartition(":")
        if not port.isdigit():
            raise ValueError(f"bad target '{spec}': port must be numeric")
        return Target(host, int(port))
    return Target(t, default_port)


def load_targets_file(path: str, default_port: int = 443) -> list[Target]:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"targets file not found: {path}")
    out: list[Target] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(parse_target(line, default_port))
    return sorted_unique(out)


def sorted_unique(targets: list[Target]) -> list[Target]:
    return sorted(set(targets))
