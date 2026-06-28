#!/usr/bin/env python3
"""Voidseal host OUTPUT reader. Takes the raw "outbox" bytes the orchestrator read off the DETACHED OUTPUT
VHDX (via the ReadVhdxRawRegion backend method) and, fail-closed, materializes the gate's input:
<out>/verdicts.json + <out>/staging/<candidate> for each whitelisted candidate. ANY anomaly -> nothing is
written under <out> and the process exits non-zero (mirrors how the screener fails closed). The host NEVER
mounts the guest FS; this only ever parses the memory-safe outbox container (guest/outbox.py)."""
import sys, argparse, pathlib, shutil, json

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "guest"))
import outbox  # guest/outbox.py — the single source of truth for the container format

def main(argv=None):
    ap = argparse.ArgumentParser(description="Parse a Voidseal outbox blob into <out>/verdicts.json + <out>/staging.")
    ap.add_argument("--blob", required=True, help="path to the raw outbox bytes read off the OUTPUT VHDX")
    ap.add_argument("--out", required=True, help="host output dir (verdicts.json + staging/ written here)")
    ap.add_argument("--allowed", default=None, help="optional comma-separated logical-name allowlist")
    args = ap.parse_args(argv)

    out = pathlib.Path(args.out)
    staging = out / "staging"
    try:
        blob = pathlib.Path(args.blob).read_bytes()
        allowed = set(args.allowed.split(",")) if args.allowed else None
        # outbox.read_and_verify fails closed: bad magic/version/bounds, per-entry SHA mismatch, bad name,
        # name not in allowlist, or a missing verdicts.json all raise OutboxError.
        verdicts_obj, candidates = outbox.read_and_verify(blob, allowed_names=allowed)
    except Exception as e:                       # OutboxError | OS error | JSON error -> fail closed
        # Emit NOTHING under <out> (no partial staging the gate could mis-read as a real release).
        shutil.rmtree(out, ignore_errors=True)
        print(f"read_outbox: FAIL-CLOSED: {type(e).__name__}: {e}", file=sys.stderr)
        return 2

    # Success: write the gate's inputs (clean dir, then materialize).
    shutil.rmtree(out, ignore_errors=True)
    staging.mkdir(parents=True, exist_ok=True)
    (out / "verdicts.json").write_text(json.dumps(verdicts_obj), encoding="utf-8")
    for name, data in candidates.items():
        # name already passed outbox's strict charset (no path sep / '..'); re-guard against escape anyway.
        target = staging / name
        if target.resolve().parent != staging.resolve():
            shutil.rmtree(out, ignore_errors=True)
            print(f"read_outbox: FAIL-CLOSED: candidate '{name}' escapes staging", file=sys.stderr)
            return 2
        target.write_bytes(data)
    return 0

if __name__ == "__main__":
    sys.exit(main())
