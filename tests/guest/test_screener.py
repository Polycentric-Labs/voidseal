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
import sys, json, hashlib, subprocess, pathlib

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


# --- C2.2: verdict.sha256 <-> content binding (producer side) -------------------------------------
# The `sha256` field is the host-verifiable binding the regenerator's content-binding clause (C2.4
# re-hash-before-release) checks against. It MUST be computed over the EXACT bytes the screener read
# (p.read_bytes()) -- the same basis outbox.py hashes in write_outbox_from_dir/pack_outbox -- so that
# "released bytes == screened bytes" is provable per file, not merely asserted. This test pins that
# basis so a future change to either hash source (e.g. switching to a normalized/decoded view, or
# hashing text instead of raw bytes) fails here rather than silently breaking the binding.

def test_verdict_sha256_is_over_the_exact_raw_bytes_screened(tmp_path):
    files = {
        "essay.txt": _PROSE,
        "creds.txt": "password=s3cr3tP@ssw0rd123\n",
        # non-UTF-8-clean bytes take the ERROR/EXTRACT_FAIL path -- the binding must still hold
        # over the raw bytes even when the screener could not decode them as text.
        "mixed.bin": _PROSE.encode("utf-8") + b"\xff\xfe\x00rawbinary",
    }
    v = _screen(tmp_path, files)
    for name, data in files.items():
        raw = data if isinstance(data, bytes) else data.encode("utf-8")
        assert v[name]["sha256"] == hashlib.sha256(raw).hexdigest(), (
            f"verdict sha256 for {name!r} does not bind to the exact screened bytes"
        )


def test_verdict_sha256_differs_when_bytes_differ_even_with_same_verdict(tmp_path):
    # A same-verdict, different-content pair must NOT collide on sha256 -- the binding is per-content,
    # not per-verdict-class (guards against an implementation that hashes something coarser, like the
    # verdict string or a fixed per-class placeholder, instead of the file's own bytes).
    v = _screen(tmp_path, {"a.txt": _PROSE, "b.txt": _PROSE + " \n"})
    assert v["a.txt"]["verdict"] == v["b.txt"]["verdict"] == "SAFE"
    assert v["a.txt"]["sha256"] != v["b.txt"]["sha256"]


# --- C2.3: NFKC + zero-width/bidi strip; screen BOTH raw and normalized views ------------------------
# Trojan-Source / homoglyph evasion hardening (Pass-3 P1#4). A hit in EITHER the raw text OR the
# NFKC-normalized, zero-width/bidi-stripped text must force HELD. This can only ADD hits relative to
# the C2.1 floor (screening only the raw view) -- it must never cause a raw-flagged file to become SAFE,
# and a clean, unobfuscated prose file must be unaffected (no false positive from normalization alone).

def test_zero_width_obfuscated_credential_missed_by_raw_is_caught_after_normalization(tmp_path):
    # U+200B (ZERO WIDTH SPACE) split inside the keyword defeats the raw regex outright but
    # disappears under NFKC + zero-width strip, exposing "password=..." to the detector.
    obfuscated = "pass​word=s3cr3tP@ssw0rd123\n"
    import re
    raw_rx = re.compile(r'(?i)(?<![A-Za-z])(secret|api[_-]?key|password|token)(?![A-Za-z])\s*[=:]\s*\S+')
    assert raw_rx.search(obfuscated) is None, "test fixture assumption broken: raw regex should NOT match"
    v = _screen(tmp_path, {"sneaky.txt": obfuscated})
    assert v["sneaky.txt"]["verdict"] == "HELD"
    assert "credential" in v["sneaky.txt"]["flags"]


def test_bidi_control_obfuscated_credential_is_caught_after_normalization(tmp_path):
    # A bidi override (U+202E RIGHT-TO-LEFT OVERRIDE, the classic "Trojan Source" character) spliced
    # into the keyword also defeats the raw regex; the strip removes it and exposes the credential.
    obfuscated = "pass‮word=s3cr3tP@ssw0rd123\n"
    import re
    raw_rx = re.compile(r'(?i)(?<![A-Za-z])(secret|api[_-]?key|password|token)(?![A-Za-z])\s*[=:]\s*\S+')
    assert raw_rx.search(obfuscated) is None, "test fixture assumption broken: raw regex should NOT match"
    v = _screen(tmp_path, {"bidi.txt": obfuscated})
    assert v["bidi.txt"]["verdict"] == "HELD"
    assert "credential" in v["bidi.txt"]["flags"]


def test_homoglyph_fullwidth_credential_is_caught_after_nfkc_normalization(tmp_path):
    # Fullwidth-form Latin letters (U+FF01-FF5E block) are a common homoglyph evasion; NFKC's
    # compatibility decomposition folds them back to standard ASCII, exposing the keyword.
    fullwidth_password = "ｐａｓｓｗｏｒｄ"  # "password" fullwidth
    obfuscated = f"{fullwidth_password}=s3cr3tP@ssw0rd123\n"
    import re
    raw_rx = re.compile(r'(?i)(?<![A-Za-z])(secret|api[_-]?key|password|token)(?![A-Za-z])\s*[=:]\s*\S+')
    assert raw_rx.search(obfuscated) is None, "test fixture assumption broken: raw regex should NOT match"
    v = _screen(tmp_path, {"homoglyph.txt": obfuscated})
    assert v["homoglyph.txt"]["verdict"] == "HELD"
    assert "credential" in v["homoglyph.txt"]["flags"]


def test_raw_flagged_credential_stays_held_screening_normalized_view_never_loosens(tmp_path):
    # SACRED invariant pin: a credential the RAW regex already catches must stay HELD once the
    # normalized-view union is added -- screening both views can only ADD hits, never remove one.
    v = _screen(tmp_path, {"creds.txt": "password=s3cr3tP@ssw0rd123\n"})
    assert v["creds.txt"]["verdict"] == "HELD"
    assert "credential" in v["creds.txt"]["flags"]


def test_clean_prose_with_ordinary_unicode_stays_safe_no_false_positive_from_normalization(tmp_path):
    # A clean prose file containing benign, non-obfuscating Unicode (accented characters, an em dash,
    # curly quotes -- normal typography, no zero-width/bidi controls, no homoglyph substitution of a
    # sensitive keyword) must remain SAFE. Screening the normalized view must not manufacture a false
    # positive out of ordinary Unicode text.
    prose_with_unicode = (
        "The café on the corner — a quiet, well-loved place — served “crème "
        "brûlée” every evening. Visitors from naïve tourists to seasoned locals "
        "agreed the atmosphere felt effortless and warm. The owner, Renée, greeted everyone by name "
        "and always asked how their day had gone. Regulars lingered for hours over coffee and quiet "
        "conversation, watching the light change outside the window as the afternoon wore on slowly.\n"
    )
    v = _screen(tmp_path, {"cafe.txt": prose_with_unicode})
    assert v["cafe.txt"]["verdict"] == "SAFE"
    assert v["cafe.txt"]["error_code"] == "NONE"
    assert v["cafe.txt"]["flags"] == []
