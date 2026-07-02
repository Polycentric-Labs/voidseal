"""Pytest for the C2.1 enum-only screener verdict (producer side).

LOCKED design (Allen, 2026-07-01) supersedes the plan's richer proposed schema
(category{10}/confidence{3}) to MINIMIZE the published leakage bound
Sigma log2(|enum_i|). The verdict enum is intentionally small and closed:

  verdict    in {SAFE, HELD, ERROR}
  error_code in {NONE, EXTRACT_FAIL, OFF_SCHEMA, DETECTOR_ERROR, UNSUPPORTED}
  flags      subset of a FIXED, bounded closed vocabulary of detector-category flags

`category` and `confidence` are DROPPED from the released verdict entirely (they widen
the bound); any per-file detail that used to live there is now folded into `flags`
(a bounded closed set) or omitted. See guest/screener.py module docstring for the
full enum definitions and the OFF_SCHEMA reservation note.
"""
import sys, json, subprocess, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The FIXED verdict schema the regenerator depends on. Pinned here so a drift in
# screener.py fails a test (this is the RED lock on the vocabulary).
_VERDICT_ENUM = {"SAFE", "HELD", "ERROR"}
_ERR_ENUM = {"NONE", "EXTRACT_FAIL", "OFF_SCHEMA", "DETECTOR_ERROR", "UNSUPPORTED"}
_FLAG_VOCAB = {
    "credential", "financial", "health", "ssn", "email", "aws_key",
    "pii", "secret", "entropy", "other",
}
_ALLOWED_KEYS = {"name", "sha256", "verdict", "error_code", "flags"}


def _screen(tmp_path, files: dict):
    staging = tmp_path / "s"
    staging.mkdir()
    for name, data in files.items():
        (staging / name).write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    out = tmp_path / "v.json"
    r = subprocess.run(
        [sys.executable, str(ROOT / "guest" / "screener.py"),
         "--in", str(staging), "--out", str(out), "--mode", "aggressive"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    return {v["name"]: v for v in json.loads(out.read_text(encoding="utf-8"))}


_PROSE = (
    "The morning light filtered gently through the tall oak trees, casting long golden shadows "
    "across the damp meadow. Birds began their chorus well before dawn, filling the air with "
    "intricate melodies that echoed through the valley below. A small stream wound quietly "
    "through the forest, its clear water tumbling over smooth stones worn by centuries of flow. "
    "The farmer rose early, as he always did, to tend the fields before the heat of the day. "
    "He walked slowly along the familiar path, breathing the cool air and listening to the world. "
    "Every season brought its own rhythm and colour, and he found deep satisfaction in each one.\n"
)


def test_verdict_object_is_enum_only(tmp_path):
    # Every field is from the fixed schema; NO free-form key or value leaks a channel.
    v = _screen(tmp_path, {"essay.txt": _PROSE, "creds.txt": "password=s3cr3tP@ssw0rd123\n"})
    for obj in v.values():
        assert set(obj) <= _ALLOWED_KEYS, f"unexpected key(s): {set(obj) - _ALLOWED_KEYS}"
        assert obj["verdict"] in _VERDICT_ENUM
        assert obj["error_code"] in _ERR_ENUM
        assert isinstance(obj["flags"], list)
        assert set(obj["flags"]) <= _FLAG_VOCAB, f"off-vocab flag: {set(obj['flags']) - _FLAG_VOCAB}"
        assert isinstance(obj["sha256"], str) and len(obj["sha256"]) == 64


def test_clean_prose_is_safe(tmp_path):
    v = _screen(tmp_path, {"essay.txt": _PROSE})
    assert v["essay.txt"]["verdict"] == "SAFE"
    assert v["essay.txt"]["error_code"] == "NONE"
    assert v["essay.txt"]["flags"] == []


def test_prose_that_is_not_utf8_clean_is_never_safe(tmp_path):
    # Prose bytes + an invalid UTF-8 sequence -> not known-extractable -> NEVER SAFE.
    # Under the minimal schema this is verdict=ERROR, error_code=EXTRACT_FAIL (fail-closed:
    # the screener could not even establish the artifact is clean text, so it must not release it).
    bad = _PROSE.encode("utf-8") + b"\xff\xfe\x00rawbinary"
    v = _screen(tmp_path, {"mixed.txt": bad})
    assert v["mixed.txt"]["verdict"] != "SAFE"
    assert v["mixed.txt"]["verdict"] == "ERROR"
    assert v["mixed.txt"]["error_code"] == "EXTRACT_FAIL"


def test_conjunction_holds_credential_still_held_with_credential_flag(tmp_path):
    v = _screen(tmp_path, {"creds.txt": "password=s3cr3tP@ssw0rd123\n"})
    assert v["creds.txt"]["verdict"] == "HELD"
    assert "credential" in v["creds.txt"]["flags"]


def test_credential_embedded_in_prose_is_held_never_safe(tmp_path):
    # A detector hit dominates the positive conjunction regardless of otherwise-clean prose.
    text = _PROSE + "\nOh, and by the way: api_key=AKIAIOSFODNN7EXAMPLE\n"
    v = _screen(tmp_path, {"prose-with-token.md": text})
    assert v["prose-with-token.md"]["verdict"] == "HELD"
    assert set(v["prose-with-token.md"]["flags"]) & {"credential", "aws_key"}


def test_non_prose_readable_content_is_held_not_safe(tmp_path):
    # Readable, UTF-8-clean, but not narrative prose (fails the supported-language/prose
    # precondition clause) -> fail-closed HELD, never SAFE-by-omission.
    csv = "date,quantity,unit_price,total\n2026-01-05,12,3.50,42.00\n2026-01-12,7,8.25,57.75\n"
    v = _screen(tmp_path, {"dump.csv": csv})
    assert v["dump.csv"]["verdict"] != "SAFE"
    assert v["dump.csv"]["verdict"] == "HELD"
    assert v["dump.csv"]["error_code"] == "UNSUPPORTED"


def test_unmappable_detector_tag_forces_sensitive_never_dropped(tmp_path, monkeypatch):
    # SACRED invariant pin: an unknown/unmappable detector tag must NEVER be silently
    # dropped or become a new free-form value -- it must force HELD with the 'other' flag,
    # keeping the flag alphabet fixed even when screen_text() grows an unmapped tag.
    sys.path.insert(0, str(ROOT / "guest"))
    import importlib
    screener = importlib.import_module("screener")
    importlib.reload(screener)

    def _fake_screen_text(t):
        return ["some_future_unmapped_detector_tag"]

    monkeypatch.setattr(screener, "screen_text", _fake_screen_text)
    staging = tmp_path / "s"
    staging.mkdir()
    (staging / "essay.txt").write_text(_PROSE, encoding="utf-8")
    out = tmp_path / "v.json"
    import argparse
    args = argparse.Namespace(inp=str(staging), out=str(out), mode="aggressive")
    screener._run(args)
    verdicts = {v["name"]: v for v in json.loads(out.read_text(encoding="utf-8"))}
    obj = verdicts["essay.txt"]
    assert obj["verdict"] == "HELD", "an unmappable detector tag must never be silently dropped"
    assert "other" in obj["flags"]
    assert set(obj["flags"]) <= _FLAG_VOCAB


def test_off_schema_reserved_not_emitted_by_producer(tmp_path):
    # OFF_SCHEMA is reserved for the host-side gate's schema validation (C2.4) -- the
    # producer (screener.py) never emits it itself.
    v = _screen(tmp_path, {"essay.txt": _PROSE, "creds.txt": "password=s3cr3tP@ssw0rd123\n"})
    for obj in v.values():
        assert obj["error_code"] != "OFF_SCHEMA"
