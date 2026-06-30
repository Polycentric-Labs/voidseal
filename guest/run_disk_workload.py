#!/usr/bin/env python3
"""Voidseal in-guest disk-mode runner — the PROCESSOR's outbox PRODUCER (seam #3). Runs the workload
(which drops candidate files into a staging dir), screens them OFFLINE (screener.py), and packs the
candidates + verdicts.json into a memory-safe outbox written to the RAW OUTPUT region the host reads
USER-SPACE (never a host FS mount). FAIL-CLOSED: a non-zero workload or screener aborts with no outbox.
--out is a FILE (mock/CI) or the raw OUTPUT block device (live — write_bytes' O_TRUNC is a no-op on a
block device, so the same path serves both; identifying the raw device in-guest is the seed runner's job)."""
import sys, json, argparse, subprocess, pathlib

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import outbox  # guest/outbox.py — the single source of truth for the container format

def run(staging, verdicts_path, out_path, screener=None, mode="aggressive", workload_argv=None):
    staging = pathlib.Path(staging)
    if workload_argv:                                  # 1. (optional) run the workload to populate staging
        if subprocess.run(workload_argv).returncode != 0:
            raise SystemExit("run_disk_workload: workload exited non-zero — failing closed (no outbox)")
    screener = screener or str(HERE / "screener.py")   # 2. screen staging -> verdicts.json (fail-closed)
    rc = subprocess.run([sys.executable, screener, "--in", str(staging), "--out", str(verdicts_path), "--mode", mode]).returncode
    if rc != 0:
        raise SystemExit(f"run_disk_workload: screener exited {rc} — failing closed (no outbox)")
    outbox.write_outbox_from_dir(str(staging), str(verdicts_path), str(out_path))   # 3. pack + write the outbox

def main(argv=None):
    ap = argparse.ArgumentParser(description="Voidseal in-guest processor producer: workload -> screener -> outbox.")
    ap.add_argument("--staging", required=True, help="dir of candidate files the workload produced")
    ap.add_argument("--verdicts", required=True, help="path to write the screener's verdicts.json")
    ap.add_argument("--out", required=True, help="outbox destination — a FILE (mock) or the raw OUTPUT device (live)")
    ap.add_argument("--screener", default=None, help="screener.py path (default: alongside this script)")
    ap.add_argument("--mode", default="aggressive", choices=["aggressive", "moderate"])
    ap.add_argument("--workload", default=None, help="optional workload argv as a JSON list (populates --staging)")
    args = ap.parse_args(argv)
    workload_argv = json.loads(args.workload) if args.workload else None
    run(args.staging, args.verdicts, args.out, args.screener, args.mode, workload_argv)
    return 0

if __name__ == "__main__":
    sys.exit(main())
