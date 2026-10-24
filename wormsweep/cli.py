from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import load_packs, sweep

SEV = ["low", "medium", "high"]


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="wormsweep", description="Offline sweep for known npm/PyPI worm and supply-chain IOCs: compromised versions in lockfiles and installed packages, dropper files, marker strings and persistence paths. Reads files only; no network.",
                                epilog="Exit codes: 0 clean, 1 findings at/above --fail-on, 2 usage error.")
    p.add_argument("-v", "--version", action="version", version=__version__)
    p.add_argument("paths", nargs="*", default=["."], help="files or directories to sweep (default: .)")
    p.add_argument("--pack", action="append", help="IOC pack JSON file (repeatable; default: all bundled packs)")
    p.add_argument("--home", nargs="?", const=str(Path.home()), help="also check host persistence paths under this home dir (default when given bare: your home)")
    p.add_argument("--no-strings", action="store_true", help="skip marker-string search (faster)")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--fail-on", choices=SEV, default="medium")
    p.add_argument("--list-packs", action="store_true", help="list loaded IOC packs and exit")
    a = p.parse_args(argv)
    try:
        packs = load_packs(a.pack)
    except (OSError, ValueError) as e:
        print(f"wormsweep: bad pack: {e}", file=sys.stderr); return 2
    if a.list_packs:
        for k in packs:
            n = sum(len(v) for v in k["_npm"].values()) + sum(len(v) for v in k["_pypi"].values())
            print(f"{k['id']}: {k['title']} ({n} package versions, {len(k['files'])} files, {len(k['strings'])} strings, {len(k['home_paths'])} host paths)")
        return 0
    for x in a.paths:
        if not Path(x).exists():
            print(f"wormsweep: not found: {x}", file=sys.stderr); return 2
    found = sweep(a.paths, packs, home=a.home, strings=not a.no_strings)
    if a.json:
        print(json.dumps({"tool": "wormsweep", "version": __version__, "packs": [k["id"] for k in packs], "findings": found}, indent=2))
    else:
        for f in found:
            print(f"{f['severity'].upper():<7}{f['kind']:<15}{f['path']}\n        {f['detail']}  [{f['pack']}]")
        print(f"wormsweep: {len(found)} finding(s) from {len(packs)} pack(s)" + ("" if found else " - nothing known found (this is not proof of a clean system)"))
    lim = SEV.index(a.fail_on)
    return 1 if any(SEV.index(f["severity"]) >= lim for f in found) else 0
