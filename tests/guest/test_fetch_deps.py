import sys, json, pathlib, hashlib, subprocess, pytest
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "guest"))
import fetch_deps  # guest/fetch_deps.py

def test_build_commands_pip_has_cross_target_flags():
    spec = {"Pip": {"Packages": ["urllib3"], "Platform": "manylinux2014_x86_64", "OnlyBinary": True,
                    "RequireHashes": True, "RequirementsFile": "requirements.txt"}}
    cmds = {f: c for f, c in fetch_deps.build_commands(spec, "/out")}
    pip = cmds["pip"]
    assert pip[:2] == ["pip", "download"]
    assert "--platform" in pip and "manylinux2014_x86_64" in pip
    assert "--only-binary=:all:" in pip and "--require-hashes" in pip
    assert "-r" in pip and "requirements.txt" in pip

def test_require_hashes_requires_a_requirements_file():
    # RequireHashes with a RequirementsFile -> pip download -r <file> --require-hashes (NO bare names)
    spec = {"Pip": {"RequireHashes": True, "RequirementsFile": "requirements.txt", "Packages": ["urllib3"]}}
    cmds = dict((f, c) for f, c in fetch_deps.build_commands(spec, "/mnt/out"))
    pip = cmds["pip"]
    assert "--require-hashes" in pip
    assert "-r" in pip and "requirements.txt" in pip           # the lockfile is passed
    assert "urllib3" not in pip                                 # bare names NOT appended in hashed mode

def test_require_hashes_without_reqfile_is_a_hard_error():
    # RequireHashes WITHOUT a RequirementsFile must FAIL (the old no-op is now rejected)
    spec = {"Pip": {"RequireHashes": True, "Packages": ["urllib3"]}}
    with pytest.raises(ValueError, match="RequireHashes.*RequirementsFile"):
        fetch_deps.build_commands(spec, "/mnt/out")

def test_hf_revision_is_pinned():
    spec = {"HuggingFace": {"Models": ["hf-internal-testing/tiny-random-gpt2"], "Revision": "a"*40}}
    cmds = dict((f, c) for f, c in fetch_deps.build_commands(spec, "/mnt/out"))
    hf = cmds["hf"]
    assert "--revision" in hf and ("a"*40) in hf

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
    spec = {"Pip": {"Packages": ["urllib3"], "Platform": "manylinux2014_x86_64", "OnlyBinary": True,
                    "RequireHashes": True, "RequirementsFile": "requirements.txt"}}
    sp = tmp_path / "spec.json"; sp.write_text(json.dumps(spec))
    out = tmp_path / "out"
    r = subprocess.run([sys.executable, str(ROOT / "guest" / "fetch_deps.py"),
                        "--spec", str(sp), "--out", str(out), "--plan"], capture_output=True, text=True)
    assert r.returncode == 0
    assert "pip download" in r.stdout and "manylinux2014_x86_64" in r.stdout
    assert not (out / "pip").exists() or not any((out / "pip").iterdir())   # --plan did NOT fetch
