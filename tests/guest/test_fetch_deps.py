import sys, json, pathlib, hashlib, subprocess
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "guest"))
import fetch_deps  # guest/fetch_deps.py

def test_build_commands_pip_has_cross_target_flags():
    spec = {"Pip": {"Packages": ["urllib3"], "Platform": "manylinux2014_x86_64", "OnlyBinary": True, "RequireHashes": True}}
    cmds = {f: c for f, c in fetch_deps.build_commands(spec, "/out")}
    pip = cmds["pip"]
    assert pip[:2] == ["pip", "download"]
    assert "--platform" in pip and "manylinux2014_x86_64" in pip
    assert "--only-binary=:all:" in pip and "--require-hashes" in pip
    assert "urllib3" in pip

def test_build_commands_apt_and_hf():
    spec = {"Apt": {"Packages": ["jq"]}, "HuggingFace": {"Models": ["hf-internal-testing/tiny-random-gpt2"]}}
    cmds = {f: c for f, c in fetch_deps.build_commands(spec, "/out")}
    assert cmds["apt"] == ["apt-get", "download", "jq"]
    assert "huggingface-cli" in cmds["hf"] and "hf-internal-testing/tiny-random-gpt2" in cmds["hf"]

def test_write_manifest_has_per_file_sha256(tmp_path):
    (tmp_path / "pip").mkdir(); (tmp_path / "pip" / "urllib3.whl").write_bytes(b"WHEEL")
    (tmp_path / "apt").mkdir(); (tmp_path / "apt" / "jq.deb").write_bytes(b"DEB")
    mp = fetch_deps.write_manifest(str(tmp_path))
    by = {e["path"]: e for e in json.loads(pathlib.Path(mp).read_text())["files"]}
    assert by["pip/urllib3.whl"]["sha256"] == hashlib.sha256(b"WHEEL").hexdigest()
    assert by["apt/jq.deb"]["size"] == 3

def test_plan_mode_prints_commands_without_executing(tmp_path):
    spec = {"Pip": {"Packages": ["urllib3"], "Platform": "manylinux2014_x86_64", "OnlyBinary": True, "RequireHashes": True}}
    sp = tmp_path / "spec.json"; sp.write_text(json.dumps(spec))
    out = tmp_path / "out"
    r = subprocess.run([sys.executable, str(ROOT / "guest" / "fetch_deps.py"),
                        "--spec", str(sp), "--out", str(out), "--plan"], capture_output=True, text=True)
    assert r.returncode == 0
    assert "pip download" in r.stdout and "manylinux2014_x86_64" in r.stdout
    assert not (out / "pip").exists() or not any((out / "pip").iterdir())   # --plan did NOT fetch
