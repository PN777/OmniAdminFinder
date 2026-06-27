#!/usr/bin/env python3
"""
OmniAdminFinder — standalone entry point.

Delegates entirely to the ``omnifinder`` package so that this file and the
``omniadminfinder`` / ``adminfinder`` console scripts always produce identical
behaviour from a single shared implementation.

IMPORTANT: For authorized security testing and defensive research only.
You must have explicit permission before scanning any target.
"""

from omnifinder.cli import main

if __name__ == "__main__":
    main()
