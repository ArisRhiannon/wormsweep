# wormsweep

**One offline command to check a repo, a CI runner or a dev machine for known npm and PyPI worm indicators.** wormsweep reads lockfiles, installed `node_modules` and `site-packages`, and looks for compromised package versions, dropper files, worm install hooks, marker strings and persistence paths published in public advisories. IOCs ship as small, reviewable JSON *packs* you can add to.

[![CI](https://github.com/ArisRhiannon/wormsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/ArisRhiannon/wormsweep/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python >= 3.9](https://img.shields.io/badge/python-%3E%3D3.9-blue)
![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![Offline](https://img.shields.io/badge/network-none-informational)

```bash
pipx run --spec git+https://github.com/ArisRhiannon/wormsweep wormsweep . --home
```

## Why

Every worm wave (Shai-Hulud, ChainDrop, the TeamPCP litellm/telnyx compromise) comes with an advisory full of bad versions, file names and domains, and responders end up grepping lockfiles by hand. wormsweep turns those lists into one repeatable, offline sweep with CI exit codes.

## Bundled IOC packs (v0.1.0)

| Pack | What it contains | Source |
|---|---|---|
| `shai-hulud-chaindrop-2026-08` | 665 npm versions verified by codelake against the Wiz list, payload names `math_init.js` / `Math_Symbol.js` / `router_runtime.js`, `preinstall` running `setup.mjs`, attacker marker strings | [codelake CLR-2026-3042](https://research.codelake.dev/advisories/clr-2026-3042-shai-hulud/) |
| `teampcp-litellm-2026-03` | `litellm` 1.82.7/1.82.8, `telnyx` 4.87.1/4.87.2, `litellm_init.pth`, C2/exfil domains, `~/.config/sysmon/sysmon.py` + systemd unit, `/tmp/pglog` | [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/), [PYSEC-2026-2](https://github.com/pypa/advisory-database/blob/main/vulns/litellm/PYSEC-2026-2.yaml) |

The Shai-Hulud pack is a **subset**: Wiz's full list has about 2,235 versions; only the 665 that codelake republished in full are included. PRs adding the rest (with a source) are very welcome.

## Usage

```bash
wormsweep                         # sweep the current directory
wormsweep ~/code ~/.npm --home    # several roots, plus host persistence paths under $HOME
wormsweep --json . > sweep.json
wormsweep --fail-on high .        # ignore medium (marker-string) hits for the exit code
wormsweep --no-strings .          # versions and files only, faster on huge trees
wormsweep --pack my-iocs.json .   # use your own pack(s) instead of the bundled ones
wormsweep --list-packs
```

Example output (illustrative):

```
HIGH   lockfile       web/package-lock.json
        npm:@ornikar/<pkg>@<ver> is a known-compromised version  [shai-hulud-chaindrop-2026-08]
HIGH   install-script node_modules/<pkg>/package.json
        preinstall runs 'setup.mjs' (worm dropper pattern): node setup.mjs  [shai-hulud-chaindrop-2026-08]
wormsweep: 2 finding(s) from 2 pack(s)
```

Exit codes: `0` nothing at or above `--fail-on` (default `medium`), `1` findings, `2` usage error.

### What it reads

- Lockfiles: `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry), `pnpm-lock.yaml`, `requirements*.txt`, `constraints*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`
- Installed packages: `node_modules/**/package.json` (name, version, install hooks) and `*.dist-info/METADATA`
- Files whose name matches a pack (scoped to `node_modules` or `site-packages` when the pack says so)
- Text files up to 4 MB for marker strings (domains, campaign signatures)
- With `--home`: host paths such as persistence scripts and systemd units

### In CI

```yaml
- run: pipx run --spec git+https://github.com/ArisRhiannon/wormsweep@v0.1.0 wormsweep .
```

## Pack format

```json
{
  "id": "my-campaign-2026-10",
  "title": "Human name",
  "sources": ["https://advisory.example/..."],
  "packages": { "npm": { "pkg": ["1.2.3"] }, "pypi": { "pkg": ["4.5.6"] } },
  "files": [{ "name": "payload.js", "severity": "high", "where": "node_modules" }],
  "install_scripts": ["setup.mjs"],
  "strings": ["campaign-marker"],
  "home_paths": [".config/evil/run.py", "/tmp/stage"]
}
```

PyPI names are compared after PEP 503 normalisation. JSON (not YAML) keeps the tool dependency-free.

## Limits

- **A clean result is not proof of a clean system.** wormsweep only knows what is in its packs; new or unlisted versions, renamed payloads and in-memory activity are invisible to it. Pair it with behavioural tools such as [wormguard](https://github.com/ArisRhiannon/wormguard).
- If a hit shows up on a machine that ran installs, treat it as compromised and rotate credentials from a clean machine.
- Packs are hand-curated from public advisories; mistakes are possible. Every entry cites its source so you can check it.
- The TeamPCP pack does not yet include that campaign's npm, Docker image, GitHub Action or OpenVSX indicators.

## Related

[lockgate](https://github.com/ArisRhiannon/lockgate) and [pylockgate](https://github.com/ArisRhiannon/pylockgate) (lockfile diff gates) · [pthwatch](https://github.com/ArisRhiannon/pthwatch) (Python start-up hooks) · [actionlock](https://github.com/ArisRhiannon/actionlock) (GitHub Actions tag pinning)

## License

[MIT](LICENSE)
