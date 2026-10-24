import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from wormsweep.cli import main
from wormsweep.core import load_packs, parse_package_lock, parse_pnpm_lock, parse_requirements, parse_toml_lock, parse_yarn_lock, sweep

PACKS = load_packs()


def tree(files):
    root = Path(tempfile.mkdtemp())
    for name, body in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(body if isinstance(body, str) else json.dumps(body))
    return root


def run(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = main(args)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class Parsers(unittest.TestCase):
    def test_package_lock_v3(self):
        t = json.dumps({"packages": {"": {}, "node_modules/@qlik/api": {"version": "1.2.3"}, "node_modules/a/node_modules/b": {"version": "2.0.0"}}})
        self.assertEqual(list(parse_package_lock(t)), [("npm", "@qlik/api", "1.2.3"), ("npm", "b", "2.0.0")])

    def test_package_lock_v1(self):
        t = json.dumps({"dependencies": {"x": {"version": "1.0.0", "dependencies": {"y": {"version": "2.0.0"}}}}})
        self.assertEqual(list(parse_package_lock(t)), [("npm", "x", "1.0.0"), ("npm", "y", "2.0.0")])

    def test_yarn_classic_and_berry(self):
        t = '"@scope/pkg@^1.0.0", "@scope/pkg@^1.1.0":\n  version "1.2.0"\n\nleft-pad@npm:^1.3.0:\n  version: 1.3.0\n'
        self.assertEqual(list(parse_yarn_lock(t)), [("npm", "@scope/pkg", "1.2.0"), ("npm", "left-pad", "1.3.0")])

    def test_pnpm(self):
        t = "packages:\n  /left-pad@1.3.0:\n    resolution: {}\n  '@scope/pkg@2.0.1':\n    resolution: {}\n  /old/1.0.0:\n    x: 1\n"
        self.assertEqual(list(parse_pnpm_lock(t)), [("npm", "left-pad", "1.3.0"), ("npm", "@scope/pkg", "2.0.1"), ("npm", "old", "1.0.0")])

    def test_requirements(self):
        t = "litellm==1.82.8 \\\n  --hash=sha256:abc\nrequests>=2\nTelnyx[extra]===4.87.1 ; python_version>'3'\n# x==1\n"
        self.assertEqual(list(parse_requirements(t)), [("pypi", "litellm", "1.82.8"), ("pypi", "Telnyx", "4.87.1")])

    def test_toml_lock(self):
        t = '[[package]]\nname = "litellm"\nversion = "1.82.7"\n\n[[package]]\nname = "x"\nversion = "1"\n'
        self.assertEqual(list(parse_toml_lock(t)), [("pypi", "litellm", "1.82.7"), ("pypi", "x", "1")])


class Sweep(unittest.TestCase):
    def kinds(self, found):
        return sorted({f["kind"] for f in found})

    def test_bundled_packs_load(self):
        ids = {p["id"] for p in PACKS}
        self.assertIn("shai-hulud-chaindrop-2026-08", ids)
        self.assertIn("teampcp-litellm-2026-03", ids)

    def test_lockfile_hit_npm(self):
        r = tree({"package-lock.json": {"packages": {"node_modules/@qlik/api": {"version": "1.75.4"}}}})
        f = sweep([r], PACKS)
        # only a hit if that version is listed; assert against the pack itself
        listed = "1.75.4" in PACKS[0]["_npm"].get("@qlik/api", set())
        self.assertEqual(bool(f), listed)

    def test_lockfile_hit_real_listed_version(self):
        name, vers = next(iter(PACKS[[p["id"] for p in PACKS].index("shai-hulud-chaindrop-2026-08")]["_npm"].items()))
        v = sorted(vers)[0]
        r = tree({"app/package-lock.json": {"packages": {f"node_modules/{name}": {"version": v}}}})
        f = sweep([r], PACKS)
        self.assertEqual(self.kinds(f), ["lockfile"])
        self.assertEqual(f[0]["severity"], "high")

    def test_unlisted_version_is_clean(self):
        r = tree({"package-lock.json": {"packages": {"node_modules/@qlik/api": {"version": "0.0.0-not-real"}}}})
        self.assertEqual(sweep([r], PACKS), [])

    def test_pypi_normalisation(self):
        r = tree({"requirements.txt": "LiteLLM==1.82.8\n", "uv.lock": '[[package]]\nname = "telnyx"\nversion = "4.87.2"\n'})
        self.assertEqual(len(sweep([r], PACKS)), 2)

    def test_installed_python_dist_info(self):
        r = tree({"venv/lib/site-packages/litellm-1.82.7.dist-info/METADATA": "Metadata-Version: 2.1\nName: litellm\nVersion: 1.82.7\n"})
        self.assertEqual(self.kinds(sweep([r], PACKS)), ["installed"])

    def test_pth_dropper_only_in_site_packages(self):
        r = tree({"lib/site-packages/litellm_init.pth": "import os\n", "docs/litellm_init.pth": "x"})
        f = [x for x in sweep([r], PACKS) if x["kind"] == "file"]
        self.assertEqual(len(f), 1)
        self.assertIn("site-packages", f[0]["path"])

    def test_install_script_and_payload_file(self):
        r = tree({"node_modules/evil/package.json": {"name": "evil", "version": "1.0.0", "scripts": {"preinstall": "node setup.mjs"}},
                  "node_modules/evil/math_init.js": "var a=1;"})
        self.assertEqual(self.kinds(sweep([r], PACKS)), ["file", "install-script"])

    def test_setup_mjs_outside_install_hook_ignored(self):
        r = tree({"node_modules/ok/package.json": {"name": "ok", "version": "1.0.0", "scripts": {"build": "node setup.mjs"}}, "src/math_init.js": "x"})
        self.assertEqual(sweep([r], PACKS), [])

    def test_marker_strings(self):
        r = tree({".vscode/tasks.json": '{"x": "Thebeautifulmarchoftime"}', "a.py": "URL='https://models.litellm.cloud/'"})
        self.assertEqual(len([x for x in sweep([r], PACKS) if x["kind"] == "string"]), 2)
        self.assertEqual([x for x in sweep([r], PACKS, strings=False) if x["kind"] == "string"], [])

    def test_host_paths(self):
        home = tree({".config/sysmon/sysmon.py": "x"})
        f = sweep([tree({})], PACKS, home=str(home))
        self.assertEqual(self.kinds(f), ["host"])

    def test_bundled_pack_files_not_self_flagged(self):
        from wormsweep.core import PACK_DIR
        self.assertEqual(sweep([PACK_DIR], PACKS), [])

    def test_custom_pack(self):
        pack = tree({"p.json": {"id": "t", "title": "t", "packages": {"npm": {"foo": ["9.9.9"]}}}}) / "p.json"
        r = tree({"yarn.lock": 'foo@^9:\n  version "9.9.9"\n'})
        self.assertEqual(len(sweep([r], load_packs([pack]))), 1)

    def test_bad_pack_rejected(self):
        bad = tree({"p.json": {"title": "no id"}}) / "p.json"
        with self.assertRaises(ValueError):
            load_packs([bad])


class Cli(unittest.TestCase):
    def test_help(self):
        code, out, _ = run(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("Offline sweep", out)

    def test_clean_exit_zero(self):
        code, out, _ = run([str(tree({"requirements.txt": "requests==2.32.0\n"}))])
        self.assertEqual(code, 0)
        self.assertIn("not proof", out)

    def test_hit_exit_one_and_json(self):
        code, out, _ = run(["--json", str(tree({"requirements.txt": "litellm==1.82.8\n"}))])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["findings"][0]["kind"], "lockfile")

    def test_fail_on_high_ignores_strings(self):
        code, _, _ = run(["--fail-on", "high", str(tree({"a.txt": "checkmarx.zone"}))])
        self.assertEqual(code, 0)

    def test_missing_path(self):
        self.assertEqual(run(["/nope/nope"])[0], 2)

    def test_list_packs(self):
        code, out, _ = run(["--list-packs"])
        self.assertEqual(code, 0)
        self.assertIn("teampcp-litellm-2026-03", out)


if __name__ == "__main__":
    unittest.main()
