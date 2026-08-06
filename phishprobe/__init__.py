#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    PhishProbe package initialiser. Exposes the public entry point so callers
    can run a full analysis with a single import:

        from phishprobe import analyze
        report = analyze(raw_email_source)

    The package is split into focused modules (parser, authentication,
    indicators, threat intelligence, scoring, reporting) orchestrated by
    orchestrator.py. This file also pins the semantic version reported by
    the /api/status endpoint.

Dependencies:
    Python 3.12 standard library only - no third-party packages.
    Imports `analyze` from the orchestrator module.

Related Files:
    orchestrator.py   (owns the end-to-end analysis pipeline)
    app.py            (HTTP server that calls analyze / analyze_header_only)
"""

import sys

# Force UTF-8 output so header content (RFC 2047, non-Latin names) prints
# without UnicodeEncodeError on Windows consoles.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from .orchestrator import analyze  # noqa: E402

__all__ = ["analyze", "__version__"]
__version__ = "3.0.0"
