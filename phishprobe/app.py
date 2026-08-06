#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    PhishProbe web application (standard library only).

    Two pages
    ---------
      /      Header Analyzer     - paste just the raw email header (+ an optional
                                   URL to check) and get a compact verdict.
      /full  Full Email Analyzer - paste the complete raw email / .eml source and
                                   get the full report (body + attachments).

    API
    ---
      GET  /api/status          {"reputation","sources","version"}
      POST /api/analyze-header  {"header": str, "url": str}  -> header report
      POST /api/analyze         {"raw": str}                 -> full report

    How it works
    ------------
    * Before any analysis the inputs are pre-scanned: every URL / domain / the
      sender IP (and file hash, for full messages) is checked against VirusTotal
      on the server, and every domain is checked for brand typosquatting.
    * All API keys live on the BACKEND only (env vars or vt_config.json) and are
      never sent to the browser.

    The HTML / CSS / JavaScript live in the ``web`` folder next to this module
    and are served from memory (cached on first request).

Dependencies:
    Python standard library only: json, os, sys, traceback, urllib.parse,
    http.server.  Imports the orchestrator and config from this package.

Related Files:
    orchestrator.py   (analyze / analyze_header_only)
    config.py         (is_vt_configured)
    __init__.py       (__version__)
    web/              (header.html, full.html, app.css, app.js, logo.png)
    run_analyzer.py   (project entry point that calls serve())
"""

import json
import os
import sys
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .config import is_vt_configured
from .orchestrator import analyze, analyze_header_only

MAX_BODY_BYTES = 4 * 1024 * 1024

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

# Simple in-memory cache for the static web files (read once, served many).
_STATIC_CACHE = {}


def _static_file(name):
    """Return the content of a web asset, cached in memory."""
    if name not in _STATIC_CACHE:
        with open(os.path.join(WEB_DIR, name), "rb") as f:
            _STATIC_CACHE[name] = f.read()
    return _STATIC_CACHE[name]


class Handler(BaseHTTPRequestHandler):
    server_version = "PhishProbe/%s" % __version__

    # -- response helpers ------------------------------------------------

    def _send(self, status, content_type, body):
        """Write a response with security headers and no caching."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status, data):
        """JSON helper used by every API endpoint."""
        self._send(status, "application/json; charset=utf-8",
                   json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def _read_json_body(self):
        """Read and parse the request body, returning (payload, error)."""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length <= 0 or length > MAX_BODY_BYTES:
            return None, "Payload too large or empty"
        try:
            return json.loads(self.rfile.read(length).decode("utf-8")), None
        except Exception:
            return None, "Request body is not valid JSON"

    # -- routes ----------------------------------------------------------

    def do_GET(self):
        # Use only the path (drop any query string) for routing.
        path = urllib.parse.urlparse(self.path).path

        if path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", _static_file("header.html"))
        elif path == "/full":
            self._send(200, "text/html; charset=utf-8", _static_file("full.html"))
        elif path == "/app.css":
            self._send(200, "text/css; charset=utf-8", _static_file("app.css"))
        elif path == "/app.js":
            self._send(200, "application/javascript; charset=utf-8",
                       _static_file("app.js"))
        elif path == "/logo.png":
            self._send(200, "image/png", _static_file("logo.png"))
        elif path == "/api/status":
            self._send_json(200, {
                "reputation": "active" if is_vt_configured() else "inactive",
                "sources": ["VirusTotal"],
                "version": __version__,
            })
        else:
            self._send(404, "text/plain; charset=utf-8", b"Not found")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/api/analyze-header":
            self._analyze_header()
        elif path == "/api/analyze":
            self._analyze_full()
        else:
            self._send(404, "text/plain; charset=utf-8", b"Not found")

    def _analyze_header(self):
        """POST /api/analyze-header - analyze a header and/or a URL.

        Not every field is mandatory: a pasted header alone, a URL alone, or
        both are all accepted. With only a URL the report focuses on that
        indicator's reputation and typosquatting checks.
        """
        payload, error = self._read_json_body()
        if error:
            self._send_json(400, {"error": error})
            return
        header_text = (payload.get("header") or "").strip()
        url = (payload.get("url") or "").strip()
        if not header_text and not url:
            self._send_json(400, {"error": "Paste an email header, a URL, or both."})
            return
        try:
            self._send_json(200, analyze_header_only(header_text, url))
        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            self._send_json(500, {"error": str(exc)})

    def _analyze_full(self):
        """POST /api/analyze - analyze a complete raw email / .eml source."""
        payload, error = self._read_json_body()
        if error:
            self._send_json(400, {"error": error})
            return
        raw = (payload.get("raw") or "").strip()
        if not raw:
            self._send_json(400, {"error": "No email provided"})
            return
        try:
            self._send_json(200, analyze(raw))
        except Exception as exc:
            traceback.print_exc(file=sys.stderr)
            self._send_json(500, {"error": str(exc)})

    def log_message(self, fmt, *args):
        sys.stderr.write("[server] %s - %s\n" % (self.address_string(), fmt % args))


def serve(host="127.0.0.1", port=8000):
    print("=" * 66)
    print("  PhishProbe - email threat analyzer")
    print(f"  Header analyzer: http://{host}:{port}/")
    print(f"  Full email analyzer: http://{host}:{port}/full")
    print("  Threat intel: VirusTotal v3")
    print("  API keys: loaded from env or *_config.json (backend only).")
    print("=" * 66)
    try:
        ThreadingHTTPServer((host, port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
