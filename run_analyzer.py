#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    PhishProbe entry point.  Starts the web application (standard library only).

    Run:  python run_analyzer.py                 (http://127.0.0.1:8000)
          python run_analyzer.py --port 9000 --host 0.0.0.0

Dependencies:
    Python standard library only: os, sys.  Imports ``phishprobe.app.serve``.

Related Files:
    phishprobe/app.py        (serve() - the web server)
    phishprobe/__init__.py   (package version)
    vt_config.json           (optional local VirusTotal key, backend only)
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from phishprobe.app import serve


def main():
    host, port = "127.0.0.1", 8000
    args = sys.argv[1:]
    if "--host" in args:
        host = args[args.index("--host") + 1]
    if "--port" in args:
        port = int(args[args.index("--port") + 1])
    serve(host, port)


if __name__ == "__main__":
    main()
