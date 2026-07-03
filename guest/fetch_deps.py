#!/usr/bin/env python3
"""Voidseal Tier-1 builder dep-fetch runner (in-guest). Reads a deps-spec.json, fetches each dependency
over the builder's Squid SNI egress into /mnt/out/<fetcher>/, then writes a per-file SHA-256
deps-manifest.json. build_commands + write_manifest are PURE (unit-tested, no network); the subprocess
EXECUTION is live (Phase 6). --plan prints the commands and exits without executing (mock + operator preview)."""
import sys, json, argparse, pathlib, hashlib, subprocess

def build_commands(spec, out_dir):
    """deps-spec dict -> [(fetcher, argv), ...]. pip wheels cross-target the AIR-GAPPED processor, not the builder."""
    out = pathlib.Path(out_dir)
    cmds = []
    pip = spec.get("Pip")
    if pip:
        argv = ["pip", "download", "-d", str(out / "pip")]
        if pip.get("Platform"):    argv += ["--platform", pip["Platform"]]
        if pip.get("OnlyBinary"):  argv += ["--only-binary=:all:"]
        if pip.get("RequireHashes"):
            # --require-hashes is a NO-OP unless it's driving a hashed lockfile: pip only enforces
            # hashes when EVERY requirement in the resolved set carries a --hash, which only a
            # `pip-compile --generate-hashes` requirements file provides. Appending it after bare
            # package names (the old behavior) enforced NOTHING — fail closed instead.
            reqfile = pip.get("RequirementsFile")
            if not reqfile:
                raise ValueError("Pip.RequireHashes=True requires a Pip.RequirementsFile (a pip-compile "
                                 "--generate-hashes lockfile); --require-hashes is a no-op without -r. "
                                 "Provide the hashed requirements file or set RequireHashes=False.")
            argv += ["--require-hashes", "-r", reqfile]         # hashed lockfile drives the closure
        else:
            argv += list(pip.get("Packages", []))               # unhashed: bare names (dev/preview only)
        cmds.append(("pip", argv))
    apt = spec.get("Apt")
    if apt:
        cmds.append(("apt", ["apt-get", "download"] + list(apt.get("Packages", []))))   # writes .deb into CWD (main cds to out/apt)
    hf = spec.get("HuggingFace")
    if hf:
        rev = hf.get("Revision")
        for model in hf.get("Models", []):
            argv = ["huggingface-cli", "download", model,
                    "--local-dir", str(out / "hf" / model.replace("/", "__"))]
            if rev:
                argv += ["--revision", rev]                     # full commit SHA -> immutable snapshot
            cmds.append(("hf", argv))
    return cmds

def write_manifest(out_dir, manifest_path=None):
    """Walk every file under out_dir, SHA-256 it, write deps-manifest.json. Returns the manifest path."""
    out = pathlib.Path(out_dir)
    entries = []
    for p in sorted(out.rglob("*")):
        if p.is_file() and p.name != "deps-manifest.json":
            data = p.read_bytes()
            entries.append({"path": str(p.relative_to(out)).replace("\\", "/"),
                            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    mp = pathlib.Path(manifest_path) if manifest_path else (out / "deps-manifest.json")
    mp.write_text(json.dumps({"files": entries}, indent=2, sort_keys=True), encoding="utf-8")
    return str(mp)

def main(argv=None):
    ap = argparse.ArgumentParser(description="Voidseal builder dep-fetch runner.")
    ap.add_argument("--spec", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--plan", action="store_true", help="print the fetch commands and exit (no execution)")
    args = ap.parse_args(argv)
    spec = json.loads(pathlib.Path(args.spec).read_text(encoding="utf-8"))
    out = pathlib.Path(args.out); out.mkdir(parents=True, exist_ok=True)
    cmds = build_commands(spec, str(out))
    if args.plan:
        for fetcher, cmd in cmds:
            print(f"{fetcher}: {' '.join(cmd)}")
        return 0
    for fetcher, cmd in cmds:                       # LIVE (Phase 6): execute each fetch over the Squid egress
        cwd = None
        if fetcher == "apt":
            cwd = str(out / "apt"); pathlib.Path(cwd).mkdir(parents=True, exist_ok=True)
        r = subprocess.run(cmd, cwd=cwd)
        if r.returncode != 0:
            print(f"fetch_deps: FAIL-CLOSED: {fetcher} fetch exited {r.returncode}", file=sys.stderr)
            return 2
    write_manifest(str(out))
    return 0

if __name__ == "__main__":
    sys.exit(main())
