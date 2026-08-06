#!/usr/bin/env python3
"""
Author: Sathyanarayana

Description:
    Backend configuration loader. Reads the secrets the analyzers need from the
    environment or from a JSON config file. Secrets stay on the BACKEND only -
    they are never included in API responses or sent to the browser.

    Supported secret:
      * VirusTotal API key  -> env VT_API_KEY or the "virustotal_api_key"
                               field of vt_config.json

    Precedence: environment variable wins, then the config file. Config files
    are searched next to the package, in the project root, and in the current
    working directory, so the project runs from any of those locations.

Dependencies:
    Python standard library only: json, os.

Related Files:
    vt_config.json       (optional local file that holds the API key)
    virustotal.py        (consumes get_vt_api_key() for every HTTP call)
    app.py               (uses is_vt_configured() for the /api/status endpoint)
    orchestrator.py      (uses is_vt_configured() to decide lookup behaviour)
"""

import json
import os

_CONFIG = {}


def _candidates():
    """Config file paths, from the package outward to the working directory."""
    here = os.path.dirname(os.path.abspath(__file__))
    return [
        os.path.join(here, "vt_config.json"),
        os.path.join(here, os.pardir, "vt_config.json"),
        os.path.join(os.getcwd(), "vt_config.json"),
    ]


def load_config():
    """
    Merge environment overrides with the JSON config files.

    Environment variables are the highest priority because they are how most
    production / CI setups inject secrets. A config file value is only used
    when no environment value exists for the same key.
    """
    cfg = {}

    # Environment overrides (highest priority).
    for env, key in (("VT_API_KEY", "virustotal_api_key"),):
        val = os.environ.get(env)
        if val:
            cfg[key] = val.strip()

    # Config files (lower priority).  The first file that provides a key wins;
    # a malformed file is skipped so one bad file cannot break the app.
    for path in _candidates():
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for key, value in data.items():
                if key not in cfg and value:
                    cfg[key] = value
        except Exception:
            continue

    return cfg


def get_config():
    """Return the loaded backend configuration (cached after first call)."""
    if not _CONFIG:
        _CONFIG.update(load_config())
    return dict(_CONFIG)


def get_vt_api_key():
    """Return the configured VirusTotal API key ('' when none is set)."""
    return str(get_config().get("virustotal_api_key", "") or "").strip()


def is_vt_configured():
    """True when a VirusTotal API key is configured."""
    return bool(get_vt_api_key())


def reset_config():
    """Drop the cached config so it is reloaded on the next call (tests)."""
    _CONFIG.clear()
