import sys, pathlib, hashlib, struct, pytest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "guest"))
import outbox

# ---------------------------------------------------------------------------
# Helper: assemble a raw blob that bypasses pack_outbox guards
# ---------------------------------------------------------------------------
def _forge(records, total, payload):
    """records: list of (name_bytes_40, off, length, sha32). total/payload may be
    inconsistent on purpose to exercise fail-closed branches in unpack_outbox."""
    head = outbox._HEADER.pack(outbox.MAGIC, outbox.VERSION, 0, len(records), total)
    table = b"".join(outbox._REC.pack(nb, off, length, sha) for (nb, off, length, sha) in records)
    return head + table + payload

def test_round_trip_preserves_names_and_bytes():
    entries = [("verdicts.json", b'[{"name":"a.txt","verdict":"SAFE","detectors":[]}]'),
               ("a.txt", b"hello world\n")]
    blob = outbox.pack_outbox(entries)
    out = outbox.unpack_outbox(blob, allowed_names={"verdicts.json", "a.txt"})
    assert out == {"verdicts.json": entries[0][1], "a.txt": entries[1][1]}

def test_tampered_payload_byte_is_rejected():
    blob = bytearray(outbox.pack_outbox([("a.txt", b"hello world\n")]))
    blob[-1] ^= 0xFF
    with pytest.raises(outbox.OutboxError):
        outbox.unpack_outbox(bytes(blob))

def test_name_with_path_separator_is_rejected_on_pack():
    for bad in ["../etc/passwd", "a/b.txt", "a\\b.txt", "c:evil", "..", ""]:
        with pytest.raises(outbox.OutboxError):
            outbox.pack_outbox([(bad, b"x")])

def test_name_not_in_allowlist_is_rejected_on_unpack():
    blob = outbox.pack_outbox([("secret.txt", b"x")])
    with pytest.raises(outbox.OutboxError):
        outbox.unpack_outbox(blob, allowed_names={"verdicts.json"})

def test_bad_magic_and_version_are_rejected():
    blob = bytearray(outbox.pack_outbox([("a.txt", b"x")]))
    bad_magic = b"XXXXXXXX" + bytes(blob[8:])
    with pytest.raises(outbox.OutboxError):
        outbox.unpack_outbox(bytes(bad_magic))
    blob[8:10] = struct.pack("<H", 999)
    with pytest.raises(outbox.OutboxError):
        outbox.unpack_outbox(bytes(blob))

def test_truncated_blob_is_rejected():
    blob = outbox.pack_outbox([("a.txt", b"hello")])
    with pytest.raises(outbox.OutboxError):
        outbox.unpack_outbox(blob[:-3])

def test_oversize_count_is_rejected():
    with pytest.raises(outbox.OutboxError):
        outbox.pack_outbox([(f"f{i}.txt", b"x") for i in range(outbox.MAX_ENTRIES + 1)])

def test_write_from_dir_and_read_and_verify(tmp_path):
    staging = tmp_path / "staging"; staging.mkdir()
    (staging / "a.txt").write_bytes(b"hello")
    (staging / "b.txt").write_bytes(b"world")
    verdicts = tmp_path / "verdicts.json"
    verdicts.write_text('[{"name":"a.txt","verdict":"SAFE","detectors":[]}]')
    out = tmp_path / "outbox.bin"
    outbox.write_outbox_from_dir(str(staging), str(verdicts), str(out))
    vobj, cands = outbox.read_and_verify(out.read_bytes(),
                                         allowed_names={"verdicts.json", "a.txt", "b.txt"})
    assert vobj == [{"name": "a.txt", "verdict": "SAFE", "detectors": []}]
    assert cands == {"a.txt": b"hello", "b.txt": b"world"}

# ---------------------------------------------------------------------------
# Forged-blob fail-closed tests (bypass pack_outbox guards via raw bytes)
# ---------------------------------------------------------------------------

def test_invalid_utf8_name_raises_outboxerror():
    """An entry name field containing invalid UTF-8 must raise OutboxError, not UnicodeDecodeError."""
    bad_name = (b"\xff\xfe" + b"\x00" * 38)  # 40 bytes, invalid UTF-8
    sha_empty = hashlib.sha256(b"").digest()
    blob = _forge([(bad_name, 0, 0, sha_empty)], total=0, payload=b"")
    with pytest.raises(outbox.OutboxError):
        outbox.unpack_outbox(blob)

def test_unpack_rejects_duplicate_names_in_table():
    """Two records with the same logical name must raise OutboxError (duplicate guard)."""
    name_b = b"a.txt".ljust(40, b"\x00")
    sha_empty = hashlib.sha256(b"").digest()
    blob = _forge(
        [(name_b, 0, 0, sha_empty), (name_b, 0, 0, sha_empty)],
        total=0,
        payload=b"",
    )
    with pytest.raises(outbox.OutboxError):
        outbox.unpack_outbox(blob)

def test_unpack_rejects_entry_range_past_payload():
    """off+length > total must raise OutboxError even when blob length == declared size."""
    name_b = b"a.txt".ljust(40, b"\x00")
    payload = b"hello"
    # off=0, length=10 > total=5 → range check must fire
    sha = hashlib.sha256(b"hello").digest()
    blob = _forge([(name_b, 0, 10, sha)], total=5, payload=payload)
    with pytest.raises(outbox.OutboxError):
        outbox.unpack_outbox(blob)

# ---------------------------------------------------------------------------
# C1.5 / M1: pin the record-layout sizes outbox.py is the single source of truth for. Any consumer
# that restates these sizes in a comment (scripts/Invoke-Voidseal.ps1's Read-OutboxToGateInput) must
# match them exactly — this test fails if outbox.py's structs ever drift from the documented 24/104,
# which is the same drift class that caused the M1 stale-comment bug this task fixes.
def test_header_and_record_sizes_match_the_documented_layout():
    assert outbox._HEADER.size == 24, "header layout: magic[8]+version[2]+reserved[2]+count[4]+total[8] = 24"
    assert outbox._REC.size == 104, "record layout: name[40]+offset[8]+length[8]+sha256[32]+reserved[16] = 104"

# ---------------------------------------------------------------------------
# workload.json: the entrypoint's exit code rides the container as a small fixed-name entry
# ---------------------------------------------------------------------------

def _dir_outbox(tmp_path, workload_rc=None, files=None):
    staging = tmp_path / "staging"; staging.mkdir(exist_ok=True)
    for name, data in (files or {"result.html": b"<html>ok</html>"}).items():
        (staging / name).write_bytes(data)
    verdicts = tmp_path / "verdicts.json"; verdicts.write_text("[]")
    out = tmp_path / "outbox.bin"
    outbox.write_outbox_from_dir(str(staging), str(verdicts), str(out), workload_rc=workload_rc)
    return out.read_bytes()

def test_workload_exit_code_round_trips_and_is_not_a_candidate(tmp_path):
    blob = _dir_outbox(tmp_path, workload_rc=3)
    vobj, cands, rc = outbox.read_and_verify_full(blob)
    assert rc == 3
    assert vobj == []
    assert set(cands) == {"result.html"}, "workload.json is metadata, never a releasable candidate"
    # The two-value form keeps its old contract: the entry is validated, then left out of the candidates.
    vobj2, cands2 = outbox.read_and_verify(blob)
    assert (vobj2, set(cands2)) == ([], {"result.html"})

def test_exit_code_zero_is_recorded_as_zero_not_as_absent(tmp_path):
    _v, _c, rc = outbox.read_and_verify_full(_dir_outbox(tmp_path, workload_rc=0))
    assert rc == 0 and rc is not None

def test_no_exit_code_recorded_reads_back_as_none(tmp_path):
    _v, cands, rc = outbox.read_and_verify_full(_dir_outbox(tmp_path))
    assert rc is None
    assert set(cands) == {"result.html"}

def test_pack_workload_meta_rejects_out_of_range_and_non_int_codes():
    for bad in [-1, 256, 1000, True, False, "1", 1.0, None]:
        with pytest.raises(outbox.OutboxError):
            outbox.pack_workload_meta(bad)
    for good in [0, 1, 127, 255]:
        assert outbox.parse_workload_meta(outbox.pack_workload_meta(good)) == good

def test_parse_workload_meta_rejects_every_other_shape():
    bad_entries = [
        b"", b"not json", b"\xff\xfe", b"[]", b"3", b"null", b'"exit_code"',
        b"{}", b'{"exit_code":-1}', b'{"exit_code":256}', b'{"exit_code":"3"}',
        b'{"exit_code":3.0}', b'{"exit_code":true}', b'{"exit_code":null}',
        b'{"exit_code":3,"extra":1}', b'{"code":3}',
        b'{"exit_code":3}' + b" " * outbox.META_MAX_BYTES,       # over the size bound
    ]
    for data in bad_entries:
        with pytest.raises(outbox.OutboxError):
            outbox.parse_workload_meta(data)

def test_parse_error_messages_never_echo_the_entry_bytes():
    secret = b'{"exit_code":"SECRET-TOKEN-123"}'
    with pytest.raises(outbox.OutboxError) as ei:
        outbox.parse_workload_meta(secret)
    assert "SECRET-TOKEN-123" not in str(ei.value)

def test_a_malformed_workload_entry_in_a_blob_fails_the_whole_read():
    blob = outbox.pack_outbox([("verdicts.json", b"[]"), ("workload.json", b'{"exit_code": 999}'), ("a.txt", b"x")])
    with pytest.raises(outbox.OutboxError):
        outbox.read_and_verify_full(blob)
    with pytest.raises(outbox.OutboxError):
        outbox.read_and_verify(blob)

def test_a_staged_file_may_not_use_the_reserved_workload_name(tmp_path):
    for rc in (None, 0):
        t = tmp_path / f"rc{rc}"; t.mkdir()
        with pytest.raises(outbox.OutboxError):
            _dir_outbox(t, workload_rc=rc, files={"workload.json": b'{"exit_code":0}', "result.html": b"x"})
        assert not (t / "outbox.bin").exists(), "fail-closed: no outbox is written"

def test_the_allowlist_covers_workload_json_like_any_other_entry(tmp_path):
    blob = _dir_outbox(tmp_path, workload_rc=1)
    with pytest.raises(outbox.OutboxError):
        outbox.read_and_verify_full(blob, allowed_names={"verdicts.json", "result.html"})
    _v, _c, rc = outbox.read_and_verify_full(blob, allowed_names={"verdicts.json", "result.html", "workload.json"})
    assert rc == 1

def test_the_meta_entry_stays_inside_the_container_bounds(tmp_path):
    # verdicts.json and workload.json both count toward MAX_ENTRIES: 254 staged files is the most that fit.
    files = {f"f{i}.txt": b"x" for i in range(outbox.MAX_ENTRIES - 2)}
    _dir_outbox(tmp_path, workload_rc=0, files=files)               # 254 + verdicts + workload = 256: fits
    t2 = tmp_path / "over"; t2.mkdir()
    files[f"f{outbox.MAX_ENTRIES}.txt"] = b"x"                       # one more: 257 entries
    with pytest.raises(outbox.OutboxError):
        _dir_outbox(t2, workload_rc=0, files=files)
    assert len(outbox.pack_workload_meta(255)) <= outbox.META_MAX_BYTES
