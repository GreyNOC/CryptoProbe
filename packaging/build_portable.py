"""Build a single-file portable CryptoProbe binary with PyInstaller.

Mirrors CryptoScan's packaging/build_portable.py so a field/Termux/air-gapped
operator gets one static artifact. The conformance packs + FIPS dataset are
bundled as data files (they ship inside the wheel via package-data too).

Usage:  python packaging/build_portable.py [--name cp]
Note:   completed-handshake evidence still requires a system openssl >= 3.5 at
        runtime; the raw-probe + classification path is fully self-contained.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "packaging" / "cp_entry.py"
PACKS = ROOT / "cryptoprobe" / "packs"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="cp")
    ap.add_argument("--distpath", default=str(ROOT / "portable"))
    args = ap.parse_args()

    sep = ";" if os.name == "nt" else ":"
    add_data = f"{PACKS}{sep}cryptoprobe/packs"
    cmd = [
        sys.executable, "-m", "PyInstaller", "--onefile", "--console",
        "--name", args.name, "--distpath", args.distpath,
        "--paths", str(ROOT),
        "--collect-submodules", "cryptoprobe",
        "--add-data", add_data,
        str(ENTRY),
    ]
    print("[*] " + " ".join(cmd))
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
