#!/usr/bin/env python3
"""Stand-in for voidseal_egress_proxy.py in tests/fixtures/Invoke-RealEgressCapture.ps1.

It opens no socket. It writes the ready file the real proxy writes (pid, host, port), then waits for
the stop file and exits 0, so the REAL StartEgressProxy / StopEgressProxy bodies can be run against a
genuine child process. Flags steer the failure paths:
  --exit-early      exit 4 before writing the ready file
  --never-ready     never write the ready file (the start must time out and kill it)
  --ignore-stop     ignore the stop file (the stop must kill it)
  --wrong-pid       write a pid that is not this process's
"""
import json
import os
import sys
import time


def arg(name):
    if name in sys.argv:
        i = sys.argv.index(name)
        return sys.argv[i + 1] if i + 1 < len(sys.argv) else None
    return None


def main():
    if "--exit-early" in sys.argv:
        return 4
    ready = arg("--ready-file")
    stop = arg("--stop-file")
    if ready and "--never-ready" not in sys.argv:
        pid = os.getpid() + (100000 if "--wrong-pid" in sys.argv else 0)
        with open(ready + ".tmp", "w", encoding="utf-8") as fh:
            json.dump({"pid": pid, "host": arg("--listen-host"), "port": 13128}, fh)
        os.replace(ready + ".tmp", ready)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if stop and os.path.exists(stop) and "--ignore-stop" not in sys.argv:
            return 0
        time.sleep(0.05)
    return 0


if __name__ == "__main__":
    sys.exit(main())
