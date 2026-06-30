"""Thin launcher for the portable (PyInstaller) build.

Mirrors CryptoScan's packaging/gs_entry.py: the portable binary calls this
instead of the installed console_scripts entry point.
"""

import sys

from cryptoprobe.cli import main

if __name__ == "__main__":
    sys.exit(main())
