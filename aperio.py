#!/usr/bin/env python3
"""Aperio entry point.

    python aperio.py                                  # desktop GUI
    python aperio.py --ui                             # desktop GUI
    python aperio.py <file-or-dir> [--out DIR] [--jobs N]
    python aperio.py --doctor
    python aperio.py --setup
"""
import sys

if sys.version_info < (3, 11):
    sys.exit("Aperio requires Python 3.11+")

from aperio.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
