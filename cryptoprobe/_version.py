"""Single source of truth for the package version.

Kept in its own module so cli.py / manifest.py / cbom.py can import it without
creating an import cycle through the package __init__. Mirrors the CryptoScan
convention (cryptoscan/_version.py); the release workflow validates that this
string, pyproject.toml [project].version, and the git tag all agree.
"""

__version__ = "0.1.0"
