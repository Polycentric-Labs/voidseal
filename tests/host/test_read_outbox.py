# tests/host/test_read_outbox.py
import sys, subprocess, pathlib, json
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "guest"))
import outbox  # to build fixtures with the SAME format the entrypoint reads

def _run(blob_path, out_dir, allowed=None):
    args = [sys.executable, str(ROOT / "host" / "read_outbox.py"), "--blob", str(blob_path), "--out", str(out_dir)]
    if allowed: args += ["--allowed", ",".join(allowed)]
    return subprocess.run(args, capture_output=True, text=True)

def _blob(tmp_path):
    blob = outbox.pack_outbox([("verdicts.json", b'[{"name":"a.txt","verdict":"SAFE","detectors":[]}]'),
                               ("a.txt", b"hello world\n")])
    p = tmp_path / "raw.bin"; p.write_bytes(blob); return p

def test_happy_path_emits_verdicts_and_staging_and_exit0(tmp_path):
    out = tmp_path / "out"
    r = _run(_blob(tmp_path), out)
    assert r.returncode == 0, r.stderr
    assert json.loads((out / "verdicts.json").read_text())[0]["verdict"] == "SAFE"
    assert (out / "staging" / "a.txt").read_bytes() == b"hello world\n"

def test_tampered_blob_exits_nonzero_and_emits_nothing(tmp_path):
    raw = bytearray(outbox.pack_outbox([("verdicts.json", b"[]"), ("a.txt", b"x")]))
    raw[-1] ^= 0xFF                       # corrupt a payload byte -> SHA mismatch
    p = tmp_path / "raw.bin"; p.write_bytes(bytes(raw))
    out = tmp_path / "out"
    r = _run(p, out)
    assert r.returncode != 0
    assert not (out / "verdicts.json").exists()
    assert not (out / "staging").exists()

def test_name_not_in_allowlist_exits_nonzero(tmp_path):
    out = tmp_path / "out"
    r = _run(_blob(tmp_path), out, allowed=["verdicts.json"])   # 'a.txt' not allowed
    assert r.returncode != 0
    assert not (out / "staging").exists()
    assert not out.exists()

def test_missing_verdicts_json_exits_nonzero(tmp_path):
    blob = outbox.pack_outbox([("a.txt", b"x")])               # no verdicts.json
    p = tmp_path / "raw.bin"; p.write_bytes(blob)
    out = tmp_path / "out"
    r = _run(p, out)
    assert r.returncode != 0
    assert not out.exists()

def test_write_phase_failure_cleans_out_and_exits_nonzero(tmp_path, monkeypatch):
    import importlib.util, pathlib as _pl
    spec = importlib.util.spec_from_file_location("read_outbox", ROOT / "host" / "read_outbox.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    blob = outbox.pack_outbox([("verdicts.json", b'[{"name":"a.txt","verdict":"SAFE","detectors":[]}]'),
                               ("a.txt", b"hello")])
    bp = tmp_path / "raw.bin"; bp.write_bytes(blob)
    out = tmp_path / "out"
    real_wb = _pl.Path.write_bytes
    def boom(self, data, *a, **k):
        raise OSError("simulated disk-full mid-candidate-write")
    monkeypatch.setattr(_pl.Path, "write_bytes", boom)
    rc = mod.main(["--blob", str(bp), "--out", str(out)])
    assert rc != 0
    assert not out.exists()   # FAIL-CLOSED: nothing left under <out>
