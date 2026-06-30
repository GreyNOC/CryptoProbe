"""
GreyNOC CryptoProbe — logging + stream helpers.

CryptoScan inlined these helpers in its cli.py (``_force_utf8`` / ``_write_text``
plus ``print(..., file=sys.stderr)`` with ``[*] [+] [!] [gate]`` prefixes). We
factor them into a module because CryptoProbe is larger and several subsystems
log progress, but the prefixes and the stdout/stderr discipline are identical so
the two tools read alike.

Discipline (matches CryptoScan):
  * stdout carries ONLY the primary machine/report output (JSON, SARIF, the
    human report, the CBOM). Never log progress to stdout — it would corrupt a
    ``--format json`` pipe.
  * stderr carries all human progress, gated by verbosity.
"""

from __future__ import annotations

import sys
from pathlib import Path

# 0 = normal, 1 = -v (debug), 2 = -vv (trace).
_VERBOSITY = 0


def set_verbosity(level: int) -> None:
    global _VERBOSITY
    _VERBOSITY = max(0, int(level))


def verbosity() -> int:
    return _VERBOSITY


def force_utf8() -> None:
    """Emit UTF-8 regardless of the platform console codepage.

    Reports use '·', '—', '✓' and similar; on a legacy Windows console (cp1252)
    an unconfigured stream raises UnicodeEncodeError or prints mojibake.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass  # already-wrapped / non-reconfigurable stream — leave as is


def write_text(path: str, text: str) -> None:
    """Write UTF-8 with a trailing newline, independent of the OS locale."""
    if not text.endswith("\n"):
        text += "\n"
    Path(path).write_text(text, encoding="utf-8")


def info(msg: str) -> None:
    print(f"[*] {msg}", file=sys.stderr)


def ok(msg: str) -> None:
    print(f"[+] {msg}", file=sys.stderr)


def warn(msg: str) -> None:
    print(f"[!] {msg}", file=sys.stderr)


def gate(msg: str) -> None:
    print(f"[gate] {msg}", file=sys.stderr)


def debug(msg: str) -> None:
    if _VERBOSITY >= 1:
        print(f"[debug] {msg}", file=sys.stderr)


def trace(msg: str) -> None:
    if _VERBOSITY >= 2:
        print(f"[trace] {msg}", file=sys.stderr)
