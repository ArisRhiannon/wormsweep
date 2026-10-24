"""Offline IOC sweep: lockfiles, installed packages, dropper files, marker strings, host paths."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

PACK_DIR = Path(__file__).parent / "packs"
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".tox", ".mypy_cache"}
TEXT_EXT = {".js", ".mjs", ".cjs", ".ts", ".json", ".py", ".pth", ".sh", ".yml", ".yaml", ".txt", ".toml", ".cfg", ".md", ".service", ".env"}
MAX_TEXT = 4 * 1024 * 1024


def norm_py(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def load_packs(paths=None):
    files = [Path(p) for p in paths] if paths else sorted(PACK_DIR.glob("*.json"))
    packs = []
    for f in files:
        d = json.loads(Path(f).read_text(encoding="utf-8"))
        for k in ("id", "title", "packages"):
            if k not in d:
                raise ValueError(f"{f}: pack missing '{k}'")
        d.setdefault("files", []); d.setdefault("strings", []); d.setdefault("home_paths", []); d.setdefault("install_scripts", [])
        d["_file"] = str(f)
        d["_npm"] = {n: set(v) for n, v in d["packages"].get("npm", {}).items()}
        d["_pypi"] = {norm_py(n): set(v) for n, v in d["packages"].get("pypi", {}).items()}
        packs.append(d)
    return packs


def _f(pack, sev, kind, path, detail):
    return {"pack": pack["id"], "severity": sev, "kind": kind, "path": str(path), "detail": detail}


# ---------- lockfile / manifest parsers: yield (ecosystem, name, version) ----------

def parse_package_lock(text):
    d = json.loads(text)
    for key, v in (d.get("packages") or {}).items():
        if "node_modules/" in key and isinstance(v, dict) and v.get("version"):
            yield "npm", v.get("name") or key.rsplit("node_modules/", 1)[1], v["version"]
    def walk(deps):
        for n, v in (deps or {}).items():
            if isinstance(v, dict):
                if v.get("version"):
                    yield "npm", n, v["version"]
                yield from walk(v.get("dependencies"))
    if not d.get("packages"):
        yield from walk(d.get("dependencies"))


def parse_yarn_lock(text):
    name = None
    for line in text.splitlines():
        if line and not line[0].isspace() and not line.startswith("#") and line.rstrip().endswith(":"):
            spec = line.split(",")[0].strip().strip('"').rstrip(":").strip('"')
            m = re.match(r"(@?[^@]+)@", spec)
            name = m.group(1) if m else None
        else:
            m = re.match(r'\s+version:?\s+"?([^"\s]+)"?', line)
            if m and name:
                yield "npm", name, m.group(1)
                name = None


PNPM_KEY = re.compile(r"^\s{2}['\"]?/?(@?[^@\s'\"/]+(?:/[^@\s'\"]+)?)[@/](\d[^:()'\"\s]*)")
def parse_pnpm_lock(text):
    seen = set()
    for line in text.splitlines():
        m = PNPM_KEY.match(line)
        if m and line.rstrip().endswith(":") and m.groups() not in seen:
            seen.add(m.groups()); yield "npm", m.group(1), m.group(2)


def parse_requirements(text):
    for line in text.splitlines():
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;#\\]+)", line)
        if m:
            yield "pypi", m.group(1), m.group(2)


def parse_toml_lock(text):  # poetry.lock, uv.lock, pdm.lock
    for m in re.finditer(r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', text):
        yield "pypi", m.group(1), m.group(2)


LOCKFILES = {"package-lock.json": parse_package_lock, "npm-shrinkwrap.json": parse_package_lock, "yarn.lock": parse_yarn_lock,
             "pnpm-lock.yaml": parse_pnpm_lock, "poetry.lock": parse_toml_lock, "uv.lock": parse_toml_lock, "pdm.lock": parse_toml_lock}


def lock_parser(name):
    if name in LOCKFILES:
        return LOCKFILES[name]
    if re.match(r"(.*requirements.*|constraints.*)\.txt$", name):
        return parse_requirements
    return None


def match_pkg(packs, eco, name, ver):
    for p in packs:
        table = p["_npm"] if eco == "npm" else p["_pypi"]
        key = name if eco == "npm" else norm_py(name)
        if ver in table.get(key, ()):
            yield p


# ---------- the sweep ----------

def sweep(roots, packs, home=None, strings=True):
    findings = []
    file_iocs = [(p, f) for p in packs for f in p["files"]]
    pack_files = {Path(p["_file"]).resolve() for p in packs}
    needles = [(p, s) for p in packs for s in p["strings"]]
    for root in roots:
        root = Path(root)
        targets = [root] if root.is_file() else None
        for dirpath, dirnames, filenames in ([(str(root.parent), [], [root.name])] if targets else os.walk(root)):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            dp = Path(dirpath)
            for fn in filenames:
                path = dp / fn
                if path.resolve() in pack_files:
                    continue
                parts = set(path.parts)
                parser = lock_parser(fn)
                if parser:
                    try:
                        for eco, n, v in parser(path.read_text(encoding="utf-8", errors="replace")):
                            for p in match_pkg(packs, eco, n, v):
                                findings.append(_f(p, "high", "lockfile", path, f"{eco}:{n}@{v} is a known-compromised version"))
                    except ValueError:
                        pass
                if fn == "package.json" and "node_modules" in parts:
                    findings += _installed_npm(path, packs)
                if fn == "METADATA" and dp.name.endswith(".dist-info"):
                    findings += _installed_py(path, packs)
                for p, f in file_iocs:
                    if fn == f["name"]:
                        where = f.get("where")
                        if where == "node_modules" and "node_modules" not in parts:
                            continue
                        if where == "site-packages" and not ({"site-packages", "dist-packages"} & parts):
                            continue
                        findings.append(_f(p, f.get("severity", "high"), "file", path, f"dropper/IOC file name '{fn}'"))
                if strings and needles and (path.suffix.lower() in TEXT_EXT or fn.startswith(".")):
                    findings += _grep(path, needles)
    if home is not None:
        for p in packs:
            for hp in p["home_paths"]:
                q = Path(hp) if hp.startswith("/") else Path(home) / hp
                if q.exists():
                    findings.append(_f(p, "high", "host", q, "persistence / staging path from advisory exists"))
    # de-duplicate
    seen, out = set(), []
    for f in findings:
        k = (f["pack"], f["kind"], f["path"], f["detail"])
        if k not in seen:
            seen.add(k); out.append(f)
    return out


def _installed_npm(path, packs):
    try:
        d = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except ValueError:
        return []
    if not isinstance(d, dict):
        return []
    out = []
    n, v = d.get("name"), d.get("version")
    if isinstance(n, str) and isinstance(v, str):
        for p in match_pkg(packs, "npm", n, v):
            out.append(_f(p, "high", "installed", path, f"installed npm:{n}@{v} is a known-compromised version"))
    scripts = d.get("scripts") if isinstance(d.get("scripts"), dict) else {}
    for hook in ("preinstall", "install", "postinstall"):
        cmd = scripts.get(hook)
        if isinstance(cmd, str):
            for p in packs:
                for s in p["install_scripts"]:
                    if s in cmd:
                        out.append(_f(p, "high", "install-script", path, f"{hook} runs '{s}' (worm dropper pattern): {cmd[:80]}"))
    return out


def _installed_py(path, packs):
    text = path.read_text(encoding="utf-8", errors="replace")[:4000]
    n = re.search(r"^Name:\s*(.+)$", text, re.M); v = re.search(r"^Version:\s*(.+)$", text, re.M)
    if not (n and v):
        return []
    return [_f(p, "high", "installed", path.parent, f"installed pypi:{n.group(1).strip()}=={v.group(1).strip()} is a known-compromised version")
            for p in match_pkg(packs, "pypi", n.group(1).strip(), v.group(1).strip())]


def _grep(path, needles):
    try:
        if path.stat().st_size > MAX_TEXT:
            return []
        data = path.read_bytes()
    except OSError:
        return []
    out = []
    for p, s in needles:
        if s.encode() in data:
            out.append(_f(p, "medium", "string", path, f"contains marker string '{s}'"))
    return out
