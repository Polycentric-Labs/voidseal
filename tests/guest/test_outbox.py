import sys, pathlib, hashlib, struct, pytest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "guest"))
import outbox

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
