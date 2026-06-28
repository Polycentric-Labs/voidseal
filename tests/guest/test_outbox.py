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
