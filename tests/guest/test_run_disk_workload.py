import sys, json, hashlib, pathlib, subprocess
ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "guest"))
import outbox  # guest/outbox.py

def _run(*args):
    return subprocess.run([sys.executable, str(ROOT / "guest" / "run_disk_workload.py"), *args],
                          capture_output=True, text=True)

def test_runner_screens_and_packs_a_valid_outbox(tmp_path):
    staging = tmp_path / "staging"; staging.mkdir()
    # A clear SAFE prose file: >=60 words, alpha ratio >0.85, >=3 sentence terminators, no detector hits.
    # A clear HELD credential file: triggers the 'credential' regex via SECRET keyword (C2.1 minimal
    # enum schema: verdict in {SAFE, HELD, ERROR} -- a detector hit -> HELD, never SENSITIVE).
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
    assert by["creds.txt"] == "HELD"
    assert set(candidates) == {"essay.txt", "creds.txt"}   # the outbox carries ALL candidates; the HOST gate partitions

def test_runner_fails_closed_on_screener_error_no_outbox_written(tmp_path):
    staging = tmp_path / "s"; staging.mkdir(); (staging / "a.txt").write_text("x", encoding="utf-8")
    out = tmp_path / "o.bin"
    r = _run("--staging", str(staging), "--verdicts", str(tmp_path / "v.json"), "--out", str(out),
             "--screener", str(tmp_path / "does-not-exist.py"))   # screener subprocess -> non-zero
    assert r.returncode != 0
    assert not out.exists(), "fail-closed: no outbox is written when screening fails"

# --- C1.3: --transport-only mode (firefox — the SHARED producer template, no screener) --------------
# LOCKED design (Allen 2026-07-01): firefox's outbox transport is NOT screened. run_disk_workload.py is
# the ONE shared outbox-producer template for both the processor (screens) and firefox (transport-only,
# skips the screener entirely). guest/outbox.py's read_and_verify() unconditionally requires a
# 'verdicts.json' entry in the container (flagged by C1.2's report), so --transport-only writes a
# well-formed PLACEHOLDER verdicts.json (an honest "nothing was screened": []) instead of invoking
# screener.py, then packs staging + that placeholder into the outbox exactly like the screened path.

def test_transport_only_skips_the_screener_and_writes_a_placeholder_verdicts_json(tmp_path):
    staging = tmp_path / "staging"; staging.mkdir()
    (staging / "result.html").write_text("<!DOCTYPE NETSCAPE-Bookmark-file-1>\n<title>x</title>\n", encoding="utf-8")
    verdicts = tmp_path / "verdicts.json"; out = tmp_path / "outbox.bin"
    r = _run("--staging", str(staging), "--verdicts", str(verdicts), "--out", str(out), "--transport-only")
    assert r.returncode == 0, r.stderr

    verdicts_obj, candidates = outbox.read_and_verify(out.read_bytes())   # round-trips => a valid outbox
    assert verdicts_obj == [], "transport-only: an honest placeholder verdicts.json (nothing was screened)"
    assert set(candidates) == {"result.html"}
    assert candidates["result.html"] == (staging / "result.html").read_bytes(), "transport rides VERBATIM, not re-encoded"

def test_transport_only_never_invokes_the_screener_even_on_sensitive_looking_content(tmp_path):
    # Proves --transport-only truly bypasses screening (not just "screens and happens to pass") — a
    # credential-shaped file must ride the outbox unchanged, since firefox's outbox is transport-only
    # and its host read path never partitions on Released/Held (Invoke-Voidseal.ps1 C1.2).
    staging = tmp_path / "staging"; staging.mkdir()
    (staging / "result.html").write_bytes(b"password=s3cr3tP@ssw0rd123\n")
    verdicts = tmp_path / "verdicts.json"; out = tmp_path / "outbox.bin"
    r = _run("--staging", str(staging), "--verdicts", str(verdicts), "--out", str(out), "--transport-only",
             "--screener", str(tmp_path / "does-not-exist.py"))   # if this were ever invoked, it would fail closed
    assert r.returncode == 0, r.stderr
    verdicts_obj, candidates = outbox.read_and_verify(out.read_bytes())
    assert verdicts_obj == []
    assert candidates["result.html"] == b"password=s3cr3tP@ssw0rd123\n"

def test_transport_only_still_fails_closed_on_workload_error_no_outbox_written(tmp_path):
    # FAIL-CLOSED symmetry: --transport-only must still fail closed if the (optional) workload step
    # errors — skipping the screener must not weaken the workload-failure guard.
    staging = tmp_path / "s"; staging.mkdir()
    out = tmp_path / "o.bin"
    r = _run("--staging", str(staging), "--verdicts", str(tmp_path / "v.json"), "--out", str(out),
             "--transport-only", "--workload", json.dumps([sys.executable, "-c", "import sys; sys.exit(1)"]))
    assert r.returncode != 0
    assert not out.exists(), "fail-closed: no outbox is written when the workload step fails, even transport-only"

# --- C2.2: verdict.sha256 <-> outbox-record-sha256 reconciliation (end-to-end producer path) -------
# The screener emits `sha256` over the raw bytes it screened (C2.1/C2.2). outbox.py's pack_outbox
# independently hashes each entry's raw bytes into the container's per-record sha256 field. This test
# runs the REAL producer end-to-end (screener -> verdicts.json -> write_outbox_from_dir) and proves the
# two hashes reconcile for every screened candidate: verdict.sha256 == outbox record sha256 == the
# file's own hash. That is the content-binding contract C2.4's host re-hash checks against — a mismatch
# here would mean "screened bytes" and "released bytes" could silently diverge (the P1#3 TOCTOU gap).

def test_verdict_sha256_reconciles_with_outbox_record_sha256_for_every_candidate(tmp_path):
    staging = tmp_path / "staging"; staging.mkdir()
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
    verdicts_path = tmp_path / "verdicts.json"; out = tmp_path / "outbox.bin"
    r = _run("--staging", str(staging), "--verdicts", str(verdicts_path), "--out", str(out))
    assert r.returncode == 0, r.stderr

    verdicts_obj = json.loads(verdicts_path.read_text(encoding="utf-8"))
    assert {v["name"] for v in verdicts_obj} == {"essay.txt", "creds.txt"}

    # Re-parse the outbox with the LOW-LEVEL unpack (not read_and_verify) so we can inspect the raw
    # per-record sha256 bytes directly, independent of read_and_verify's own tamper check.
    blob = out.read_bytes()
    magic, version, _res, count, total = outbox._HEADER.unpack(blob[:outbox._HEADER.size])
    table_end = outbox._HEADER.size + count * outbox._REC.size
    record_sha_by_name = {}
    for i in range(count):
        rec = blob[outbox._HEADER.size + i * outbox._REC.size: outbox._HEADER.size + (i + 1) * outbox._REC.size]
        raw_name, off, length, want = outbox._REC.unpack(rec)
        name = raw_name.rstrip(b"\x00").decode("utf-8")
        record_sha_by_name[name] = want.hex()

    for v in verdicts_obj:
        name = v["name"]
        file_sha = hashlib.sha256((staging / name).read_bytes()).hexdigest()
        assert v["sha256"] == file_sha, f"verdict sha256 for {name!r} does not match the file's own bytes"
        assert record_sha_by_name[name] == file_sha, (
            f"outbox record sha256 for {name!r} does not match the file's own bytes"
        )
        assert v["sha256"] == record_sha_by_name[name], (
            f"verdict.sha256 != outbox record sha256 for {name!r} — content-binding contract broken"
        )
    # verdicts.json itself is also packed as an outbox entry (guest/outbox.py write_outbox_from_dir);
    # confirm its record sha256 matches its own on-disk bytes too (the container's internal integrity,
    # not the verdict<->content binding, but worth pinning alongside since it rides the same table).
    assert record_sha_by_name["verdicts.json"] == hashlib.sha256(verdicts_path.read_bytes()).hexdigest()
