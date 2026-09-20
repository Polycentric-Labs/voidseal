#!/usr/bin/env python3
"""Voidseal OUTPUT "outbox" — a tiny, memory-safe binary container the in-guest
producer writes to a RAW VHDX region and the host reads in USER-SPACE (never a
host-kernel FS mount). Per-entry SHA-256 binds each released byte to its screened
hash (P0 user-space read + P1 TOCTOU defense in one format). Fail-closed: ANY
anomaly raises OutboxError and nothing is returned."""
import re, struct, hashlib, json, pathlib

MAGIC = b"VSOUTBX1"
VERSION = 1
MAX_ENTRIES = 256
MAX_TOTAL = 64 * 1024 * 1024
_NAME_RE = re.compile(r'^[A-Za-z0-9._-]{1,40}$')
_HEADER = struct.Struct("<8sHHIQ")        # magic, version, reserved, entry_count, payload_total_len
_REC = struct.Struct("<40sQQ32s16x")      # name, offset, length, sha256, 16 reserved
assert _HEADER.size == 24 and _REC.size == 104  # actual sizes on all CPython platforms

class OutboxError(Exception):
    """Single fail-closed error type."""

def _check_name(name):
    if not isinstance(name, str) or name in ("", "..", ".") or not _NAME_RE.match(name):
        raise OutboxError(f"invalid logical name: {name!r}")
    b = name.encode("utf-8")
    if len(b) > 40:
        raise OutboxError(f"name too long: {name!r}")
    return b

def pack_outbox(entries):
    if len(entries) > MAX_ENTRIES:
        raise OutboxError(f"too many entries: {len(entries)} > {MAX_ENTRIES}")
    seen, recs, payload = set(), [], bytearray()
    for name, data in entries:
        nb = _check_name(name)
        if name in seen:
            raise OutboxError(f"duplicate name: {name!r}")
        seen.add(name)
        if not isinstance(data, (bytes, bytearray)):
            raise OutboxError(f"entry {name!r} is not bytes")
        off = len(payload)
        payload += data
        if len(payload) > MAX_TOTAL:
            raise OutboxError("payload exceeds MAX_TOTAL")
        recs.append(_REC.pack(nb.ljust(40, b"\x00"), off, len(data), hashlib.sha256(bytes(data)).digest()))
    head = _HEADER.pack(MAGIC, VERSION, 0, len(entries), len(payload))
    return head + b"".join(recs) + bytes(payload)

def unpack_outbox(blob, allowed_names=None):
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < _HEADER.size:
        raise OutboxError("blob too short for header")
    magic, version, _res, count, total = _HEADER.unpack(blob[:_HEADER.size])
    if magic != MAGIC:
        raise OutboxError("bad magic")
    if version != VERSION:
        raise OutboxError(f"unsupported version {version}")
    if count > MAX_ENTRIES or total > MAX_TOTAL:
        raise OutboxError("count/total over bound")
    table_end = _HEADER.size + count * _REC.size
    payload_end = table_end + total
    if len(blob) != payload_end:
        raise OutboxError("blob length != declared size")
    payload = blob[table_end:payload_end]
    out, seen = {}, set()
    for i in range(count):
        rec = blob[_HEADER.size + i * _REC.size: _HEADER.size + (i + 1) * _REC.size]
        raw_name, off, length, want = _REC.unpack(rec)
        try:
            name = raw_name.rstrip(b"\x00").decode("utf-8", "strict")
        except UnicodeDecodeError as e:
            raise OutboxError(f"entry name is not valid UTF-8: {e}") from e
        _check_name(name)
        if name in seen:
            raise OutboxError(f"duplicate name: {name!r}")
        seen.add(name)
        if allowed_names is not None and name not in allowed_names:
            raise OutboxError(f"name not in allowlist: {name!r}")
        if off > total or off + length > total:
            raise OutboxError(f"entry {name!r} range out of payload")
        data = bytes(payload[off:off + length])
        if hashlib.sha256(data).digest() != want:
            raise OutboxError(f"sha256 mismatch for {name!r} (tamper)")
        out[name] = data
    return out

def write_outbox_from_dir(staging_dir, verdicts_path, out_path):
    """In-guest: pack verdicts.json + every flat file in staging_dir into out_path."""
    entries = [("verdicts.json", pathlib.Path(verdicts_path).read_bytes())]
    for p in sorted(pathlib.Path(staging_dir).iterdir()):
        if p.is_file():
            entries.append((p.name, p.read_bytes()))
    pathlib.Path(out_path).write_bytes(pack_outbox(entries))

def read_and_verify(blob, allowed_names=None):
    """Host: returns (verdicts_obj, {candidate_name: bytes}); verdicts.json must be present."""
    files = unpack_outbox(blob, allowed_names=allowed_names)
    if "verdicts.json" not in files:
        raise OutboxError("outbox missing verdicts.json")
    verdicts = json.loads(files["verdicts.json"].decode("utf-8"))
    candidates = {k: v for k, v in files.items() if k != "verdicts.json"}
    return verdicts, candidates
