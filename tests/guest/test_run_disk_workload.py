import sys, json, pathlib, subprocess
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "guest"))
import outbox  # guest/outbox.py

def _run(*args):
    return subprocess.run([sys.executable, str(ROOT / "guest" / "run_disk_workload.py"), *args],
                          capture_output=True, text=True)

def test_runner_screens_and_packs_a_valid_outbox(tmp_path):
    staging = tmp_path / "staging"; staging.mkdir()
    # A clear SAFE prose file: >=60 words, alpha ratio >0.85, >=3 sentence terminators, no SENSITIVE hits.
    # A clear SENSITIVE credential file: triggers the 'credential' regex via SECRET keyword.
    (staging / "essay.txt").write_text(
        "The morning light filtered gently through the tall oak trees, casting long golden shadows "
        "across the damp meadow. Birds began their chorus well before dawn, filling the air with "
        "intricate melodies that echoed through the valley below. A small stream wound quietly "
        "through the forest, its clear water tumbling over smooth stones worn by centuries of flow. "
        "The farmer rose early, as he always did, to tend the fields before the heat of the day "
        "arrived. He walked slowly along the familiar path, breathing in the cool morning air and "
        "listening to the world come alive around him. Every season brought its own rhythm and "
        "colour, and he found deep satisfaction in witnessing each one unfold with patient care.\n",
        encoding="utf-8")
    (staging / "creds.txt").write_text("password=s3cr3tP@ssw0rd123\n", encoding="utf-8")
    verdicts = tmp_path / "verdicts.json"; out = tmp_path / "outbox.bin"
    r = _run("--staging", str(staging), "--verdicts", str(verdicts), "--out", str(out))
    assert r.returncode == 0, r.stderr
    verdicts_obj, candidates = outbox.read_and_verify(out.read_bytes())   # round-trips => a valid outbox
    by = {v["name"]: v["verdict"] for v in verdicts_obj}
    assert by["essay.txt"] == "SAFE"
    assert by["creds.txt"] == "SENSITIVE"
    assert set(candidates) == {"essay.txt", "creds.txt"}   # the outbox carries ALL candidates; the HOST gate partitions

def test_runner_fails_closed_on_screener_error_no_outbox_written(tmp_path):
    staging = tmp_path / "s"; staging.mkdir(); (staging / "a.txt").write_text("x", encoding="utf-8")
    out = tmp_path / "o.bin"
    r = _run("--staging", str(staging), "--verdicts", str(tmp_path / "v.json"), "--out", str(out),
             "--screener", str(tmp_path / "does-not-exist.py"))   # screener subprocess -> non-zero
    assert r.returncode != 0
    assert not out.exists(), "fail-closed: no outbox is written when screening fails"
