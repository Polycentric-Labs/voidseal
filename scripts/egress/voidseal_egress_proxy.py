#!/usr/bin/env python3
"""Voidseal host egress proxy: an HTTPS CONNECT allowlist proxy for a Tier-1 HostProxy sandbox.

The host runs one of these per sandbox VM, bound to the gateway address on that VM's own Internal
switch. It is the only thing the guest can reach (the host firewall and the VM port ACL allow one TCP
port on the gateway and nothing else; there is no NAT and no route), so it is where egress policy is
decided, on the host, outside the guest's trust domain.

What it does, per connection:
  * with ``--client <ip>`` (the guest's address, which the host side always passes), closes at once any
    connection whose peer address is not that IP, logging ``decision="refused"`` and ``reason="client"``
    and sending nothing. Without ``--client`` every peer is served (the test harness and manual runs).
  * reads one request head (bounded in bytes, lines and time) and accepts only
    ``CONNECT <host>:443 HTTP/1.1`` (HTTP/1.0 is accepted too, because CPython's http.client tunnels
    with it). Any other method gets 405; anything malformed gets 400; an oversized head gets 431.
  * matches the host against the run's allowlist: exact names, or explicit ``*.suffix`` rules that
    match subdomains only. Matching is case-insensitive and runs on the IDNA (ASCII) form of both
    sides. An IP literal is refused unless it is listed. Anything off the list gets 403 and is never
    resolved.
  * resolves the name itself (the guest has no resolver) and refuses the whole answer (403) when any
    address in it is private, loopback, link-local, multicast, reserved, unspecified or otherwise not
    globally routable, IPv4 or IPv6, including IPv4 addresses embedded in IPv6 (mapped, 6to4, Teredo).
    That is the DNS-rebinding guard: the guest picks a name, the host picks the address, and a name
    that points into the host's own networks is refused.
  * dials a permitted address (the address, never the name, so there is no second lookup), replies
    200 and splices bytes both ways until either side closes, the tunnel sits idle, or the total
    deadline passes. A connection cap answers 503 to the connection over the limit.
  * writes one JSON line per connection to the log: time, client, requested name, decision, reason
    code, status, upstream address, bytes up and down, duration. Never payload, never a request
    target that was not a valid CONNECT authority, never header values.

There is no plain-HTTP proxying and no TLS interception: the proxy sees the CONNECT target and byte
counts, nothing inside the tunnel.

Shutdown: SIGINT/SIGTERM (SIGBREAK on Windows), the stop file appearing, the maximum lifetime passing,
or the parent process exiting (when --parent-pid is given). Exit codes: 0 clean stop, 2 configuration
error, 3 could not bind.

Standard library only (asyncio). Tested on loopback sockets with an injected resolver and connector:
tests/host/test_egress_proxy.py.
"""
import argparse
import asyncio
import datetime
import ipaddress
import json
import os
import re
import signal
import socket
import sys
import time

DEFAULT_PORT = 443
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_TOKEN_RE = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
_KNOWN_METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH", "CONNECT"}

REASON_PHRASES = {
    200: "Connection Established",
    400: "Bad Request",
    403: "Forbidden",
    405: "Method Not Allowed",
    431: "Request Header Fields Too Large",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


# ------------------------------------------------------------------------------------------------
# names, addresses, the allowlist
# ------------------------------------------------------------------------------------------------
def normalize_name(raw):
    """Return the lowercase IDNA (ASCII) form of a DNS name, or raise ValueError.

    One trailing dot is dropped. Every label must be a letters-digits-hyphens label of 1 to 63
    characters that neither starts nor ends with a hyphen, the whole name at most 253 characters, and
    the last label must not be all digits (so numeric host forms such as 2130706433 are never names).
    """
    if not isinstance(raw, str) or not raw or len(raw) > 254:
        raise ValueError("empty or oversized name")
    name = raw[:-1] if raw.endswith(".") else raw
    if not name:
        raise ValueError("empty name")
    try:
        ascii_name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("not a valid IDNA name: %s" % exc) from None
    ascii_name = ascii_name.lower()
    if len(ascii_name) > 253:
        raise ValueError("name longer than 253 characters")
    labels = ascii_name.split(".")
    for label in labels:
        if not _LABEL_RE.fullmatch(label):
            raise ValueError("invalid label %r" % label)
    if labels[-1].isdigit():
        raise ValueError("the last label is numeric; that is an address form, not a name")
    return ascii_name


def parse_ip_literal(text):
    """Return an ip_address for an IPv4 dotted quad or a bracketed IPv6 literal, else None."""
    if text.startswith("[") and text.endswith("]"):
        try:
            return ipaddress.IPv6Address(text[1:-1])
        except ValueError:
            return None
    if text.startswith("[") or text.endswith("]"):
        return None
    try:
        return ipaddress.IPv4Address(text)
    except ValueError:
        return None


def _embedded_ipv4(addr):
    if addr.version != 6:
        return None
    for embedded in (addr.ipv4_mapped, addr.sixtofour):
        if embedded is not None:
            return embedded
    if addr.teredo is not None:
        return addr.teredo[1]
    return None


def forbidden_reason(addr):
    """Return why an address may not be dialled ('private', 'loopback', ...), or None if it may."""
    embedded = _embedded_ipv4(addr)
    if embedded is not None:
        inner = forbidden_reason(embedded)
        if inner is not None:
            return inner
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    if addr.is_private:
        return "private"
    if not addr.is_global:
        return "non-global"
    return None


class Allowlist:
    """The run's allowlist: exact names, ``*.suffix`` rules (subdomains only) and listed IP literals."""

    def __init__(self, entries):
        self.exact = set()
        self.suffixes = set()
        self.ips = set()
        entries = list(entries or [])
        if not entries:
            raise ValueError("the allowlist is empty; a HostProxy run must allow at least one name")
        for entry in entries:
            if not isinstance(entry, str) or entry != entry.strip() or not entry:
                raise ValueError("invalid allowlist entry %r" % (entry,))
            if entry.startswith("*."):
                suffix = normalize_name(entry[2:])
                if "." not in suffix:
                    raise ValueError("suffix rule %r is too broad (it names a top-level domain)" % entry)
                self.suffixes.add(suffix)
                continue
            if "*" in entry:
                raise ValueError("invalid wildcard in %r (only a leading '*.' is allowed)" % entry)
            ip = parse_ip_literal(entry)
            if ip is not None:
                self.ips.add(ip)
                continue
            self.exact.add(normalize_name(entry))

    def match_name(self, name):
        if name in self.exact:
            return True
        return any(name.endswith("." + suffix) for suffix in self.suffixes)

    def match_ip(self, addr):
        return addr in self.ips


# ------------------------------------------------------------------------------------------------
# configuration
# ------------------------------------------------------------------------------------------------
class ProxyConfig:
    def __init__(self, listen_host, listen_port, allowlist, log_path, max_connections=64,
                 header_timeout=10.0, connect_timeout=10.0, idle_timeout=120.0, total_timeout=3600.0,
                 max_header_bytes=8192, max_header_lines=64, bind_retry_seconds=0.0, client_ip=None):
        try:
            addr = ipaddress.ip_address(listen_host)
        except ValueError:
            raise ValueError("listen host %r is not an IP literal" % (listen_host,)) from None
        if addr.is_unspecified:
            raise ValueError("refusing to listen on the unspecified address %s; bind the gateway address" % addr)
        self.client_ip = None
        if client_ip is not None:
            try:
                client = ipaddress.ip_address(client_ip)
            except ValueError:
                raise ValueError("client %r is not an IP literal" % (client_ip,)) from None
            if client.is_unspecified:
                raise ValueError("refusing the unspecified address %s as the client; pass the guest address" % client)
            self.client_ip = str(client)
        if not isinstance(allowlist, Allowlist):
            raise ValueError("allowlist must be an Allowlist")
        if not (0 <= int(listen_port) <= 65535):
            raise ValueError("listen port out of range")
        for name, value in (("max_connections", max_connections), ("max_header_bytes", max_header_bytes),
                            ("max_header_lines", max_header_lines)):
            if int(value) < 1:
                raise ValueError("%s must be positive" % name)
        for name, value in (("header_timeout", header_timeout), ("connect_timeout", connect_timeout),
                            ("idle_timeout", idle_timeout), ("total_timeout", total_timeout)):
            if float(value) <= 0:
                raise ValueError("%s must be positive" % name)
        self.listen_host = str(addr)
        self.listen_port = int(listen_port)
        self.allowlist = allowlist
        self.log_path = log_path
        self.max_connections = int(max_connections)
        self.header_timeout = float(header_timeout)
        self.connect_timeout = float(connect_timeout)
        self.idle_timeout = float(idle_timeout)
        self.total_timeout = float(total_timeout)
        self.max_header_bytes = int(max_header_bytes)
        self.max_header_lines = int(max_header_lines)
        self.bind_retry_seconds = float(bind_retry_seconds)


class _Refusal(Exception):
    def __init__(self, status, reason, decision="deny", **fields):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.decision = decision
        self.fields = fields


async def default_resolver(name):
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(name, DEFAULT_PORT, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


async def default_connector(ip, port):
    return await asyncio.open_connection(ip, port)


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


# ------------------------------------------------------------------------------------------------
# the proxy
# ------------------------------------------------------------------------------------------------
class EgressProxy:
    def __init__(self, config, resolver=None, connector=None):
        self.config = config
        self._resolver = resolver or default_resolver
        self._connector = connector or default_connector
        self._server = None
        self._handlers = set()
        self._active = 0
        self._log_file = None
        self.bound_port = None

    # ---- lifecycle ----
    async def start(self):
        cfg = self.config
        if cfg.log_path:
            self._log_file = open(cfg.log_path, "a", encoding="utf-8")
        deadline = time.monotonic() + cfg.bind_retry_seconds
        while True:
            try:
                self._server = await asyncio.start_server(
                    self._accept, cfg.listen_host, cfg.listen_port, limit=cfg.max_header_bytes)
                break
            except OSError:
                # A freshly added address can still be tentative (duplicate-address detection), which
                # makes bind fail with "cannot assign requested address" for a moment. Retry briefly.
                if time.monotonic() >= deadline:
                    raise
                await asyncio.sleep(0.25)
        self.bound_port = self._server.sockets[0].getsockname()[1]

    async def stop(self):
        if self._server is not None:
            self._server.close()
        for task in list(self._handlers):
            task.cancel()
        if self._handlers:
            await asyncio.gather(*self._handlers, return_exceptions=True)
        if self._server is not None:
            try:
                await asyncio.wait_for(self._server.wait_closed(), 5)
            except (asyncio.TimeoutError, OSError):
                pass
        if self._log_file is not None:
            self._log_file.close()
            self._log_file = None

    # ---- logging ----
    def _log(self, record):
        if self._log_file is None:
            return
        try:
            self._log_file.write(json.dumps(record, sort_keys=True) + "\n")
            self._log_file.flush()
        except OSError as exc:
            print("voidseal-egress-proxy: log write failed: %s" % exc, file=sys.stderr)

    # ---- per connection ----
    async def _accept(self, reader, writer):
        task = asyncio.current_task()
        self._handlers.add(task)
        try:
            await self._handle(reader, writer)
        finally:
            self._handlers.discard(task)

    async def _handle(self, reader, writer):
        cfg = self.config
        started = time.monotonic()
        peer = writer.get_extra_info("peername")
        record = {
            "ts": _utc_now(), "client": peer[0] if peer else None, "target": None, "port": None,
            "decision": "deny", "reason": None, "status": None, "upstream_ip": None,
            "bytes_up": 0, "bytes_down": 0,
        }
        upstream_writer = None
        self._active += 1
        try:
            if cfg.client_ip is not None and not self._is_client(peer):
                # Not the guest: close without a byte in reply. A status of None skips the response.
                raise _Refusal(None, "client", decision="refused")
            if self._active > cfg.max_connections:
                raise _Refusal(503, "connection-cap")
            target, port = await self._read_request(reader, record)
            record["target"], record["port"] = (str(target) if not isinstance(target, str) else target), port
            addresses = await self._permitted_addresses(target, record)
            upstream_reader, upstream_writer, chosen = await self._dial(addresses)
            record["upstream_ip"] = chosen
            record["decision"], record["status"] = "allow", 200
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            record["reason"] = await self._splice(reader, writer, upstream_reader, upstream_writer, started, record)
        except _Refusal as refusal:
            record["reason"] = refusal.reason
            record["decision"] = refusal.decision
            record.update(refusal.fields)
            if refusal.status is not None:
                record["status"] = refusal.status
                await self._send_error(reader, writer, refusal.status)
        except asyncio.CancelledError:
            record["reason"] = "shutdown"
        except (ConnectionError, OSError):
            if record["reason"] is None:
                record["reason"] = "client-error"
        finally:
            self._active -= 1
            for w in (upstream_writer, writer):
                if w is not None:
                    w.close()
            record["duration_ms"] = int((time.monotonic() - started) * 1000)
            self._log(record)

    def _is_client(self, peer):
        """True when the connection's peer address is the configured client (compared as parsed addresses)."""
        if not peer:
            return False
        try:
            return str(ipaddress.ip_address(peer[0])) == self.config.client_ip
        except ValueError:
            return False

    async def _send_error(self, reader, writer, status):
        head = "HTTP/1.1 %d %s\r\nConnection: close\r\nContent-Length: 0\r\n" % (status, REASON_PHRASES[status])
        if status == 405:
            head += "Allow: CONNECT\r\n"
        try:
            writer.write((head + "\r\n").encode("ascii"))
            await asyncio.wait_for(writer.drain(), 2)
            # Lingering close: half-close our side, then discard (never log, never forward) a bounded
            # amount of whatever the client already sent, so closing with unread bytes does not turn
            # into a reset that eats the response before the client reads it.
            if writer.can_write_eof():
                writer.write_eof()
            budget = 65536
            deadline = time.monotonic() + 0.5
            while budget > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                chunk = await asyncio.wait_for(reader.read(min(budget, 16384)), remaining)
                if not chunk:
                    break
                budget -= len(chunk)
        except (ConnectionError, OSError, asyncio.TimeoutError, asyncio.LimitOverrunError, ValueError):
            pass

    async def _read_request(self, reader, record):
        cfg = self.config
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), cfg.header_timeout)
        except asyncio.TimeoutError:
            raise _Refusal(None, "header-timeout") from None
        except asyncio.LimitOverrunError:
            raise _Refusal(431, "header-too-large") from None
        except asyncio.IncompleteReadError:
            raise _Refusal(None, "client-closed") from None
        if len(head) > cfg.max_header_bytes:
            raise _Refusal(431, "header-too-large")
        try:
            text = head[:-4].decode("ascii")
        except UnicodeDecodeError:
            raise _Refusal(400, "malformed-request") from None
        if any(ord(ch) < 32 and ch not in "\r\n\t" or ord(ch) == 127 for ch in text):
            raise _Refusal(400, "malformed-request")
        lines = text.split("\r\n")
        if len(lines) - 1 > cfg.max_header_lines:
            raise _Refusal(431, "too-many-headers")

        parts = lines[0].split(" ")
        if parts and _TOKEN_RE.fullmatch(parts[0]) and parts[0] != "CONNECT":
            record["method"] = parts[0] if parts[0] in _KNOWN_METHODS else "other"
            raise _Refusal(405, "method-not-allowed")
        if len(parts) != 3 or not all(parts):
            raise _Refusal(400, "malformed-request-line")
        method, authority, version = parts
        record["method"] = method
        if version not in ("HTTP/1.1", "HTTP/1.0"):
            raise _Refusal(400, "bad-version")

        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if not sep or not _TOKEN_RE.fullmatch(name):
                raise _Refusal(400, "malformed-header")
            lname = name.lower()
            if lname == "transfer-encoding" or (lname == "content-length" and value.strip() != "0"):
                raise _Refusal(400, "request-body")

        host, sep, port_text = authority.rpartition(":")
        if not sep or not host or not port_text.isdigit() or len(port_text) > 5:
            raise _Refusal(400, "malformed-target")
        if port_text != str(DEFAULT_PORT):
            raise _Refusal(403, "port-not-allowed")

        ip = parse_ip_literal(host)
        if ip is not None:
            return ip, DEFAULT_PORT
        if host.startswith("[") or host.endswith("]"):
            raise _Refusal(400, "malformed-host")
        try:
            return normalize_name(host), DEFAULT_PORT
        except ValueError:
            raise _Refusal(400, "malformed-host") from None

    async def _permitted_addresses(self, target, record):
        allowlist = self.config.allowlist
        if isinstance(target, str):
            if not allowlist.match_name(target):
                raise _Refusal(403, "not-allowlisted")
            try:
                raw = await asyncio.wait_for(self._resolver(target), self.config.connect_timeout)
            except (OSError, UnicodeError, asyncio.TimeoutError):
                raise _Refusal(502, "resolve-failed") from None
            addresses = []
            for text in raw or []:
                try:
                    addresses.append(ipaddress.ip_address(text))
                except ValueError:
                    raise _Refusal(502, "resolve-failed") from None
            if not addresses:
                raise _Refusal(502, "resolve-failed")
        else:
            if not allowlist.match_ip(target):
                raise _Refusal(403, "ip-literal-not-allowlisted")
            addresses = [target]
        for addr in addresses:
            why = forbidden_reason(addr)
            if why is not None:
                raise _Refusal(403, "forbidden-address", address_class=why)
        # de-duplicate, keep order
        seen, ordered = set(), []
        for addr in addresses:
            if addr not in seen:
                seen.add(addr)
                ordered.append(addr)
        return ordered

    async def _dial(self, addresses):
        timed_out = False
        for addr in addresses:
            try:
                reader, writer = await asyncio.wait_for(
                    self._connector(str(addr), DEFAULT_PORT), self.config.connect_timeout)
                return reader, writer, str(addr)
            except asyncio.TimeoutError:
                timed_out = True
            except (OSError, ConnectionError):
                pass
        raise _Refusal(502, "connect-timeout" if timed_out else "connect-failed")

    async def _splice(self, client_reader, client_writer, up_reader, up_writer, started, record):
        cfg = self.config
        loop_clock = time.monotonic
        last = {"t": loop_clock()}

        async def pump(src, dst, key):
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    record[key] += len(data)
                    last["t"] = loop_clock()
                    dst.write(data)
                    await dst.drain()
            except (ConnectionError, OSError):
                return
            try:
                if dst.can_write_eof():
                    dst.write_eof()
            except (ConnectionError, OSError):
                pass

        tasks = {asyncio.ensure_future(pump(client_reader, up_writer, "bytes_up")),
                 asyncio.ensure_future(pump(up_reader, client_writer, "bytes_down"))}
        tick = max(0.05, min(1.0, cfg.idle_timeout / 4, cfg.total_timeout / 4))
        reason = "tunnel-closed"
        try:
            while True:
                done, _ = await asyncio.wait(tasks, timeout=tick)
                if all(t.done() for t in tasks):
                    break
                now = loop_clock()
                if now - started > cfg.total_timeout:
                    reason = "total-timeout"
                    break
                if now - last["t"] > cfg.idle_timeout:
                    reason = "idle-timeout"
                    break
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        return reason


# ------------------------------------------------------------------------------------------------
# process watchers and the command line
# ------------------------------------------------------------------------------------------------
def _parent_watch_factory(pid):
    """Return a callable that reports True once process `pid` has exited, or None if unsupported."""
    if pid is None:
        return None
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        synchronize = 0x00100000
        # The handle is opened once, now, so a later PID reuse cannot fool the watch.
        handle = kernel32.OpenProcess(synchronize, False, int(pid))
        if not handle:
            return lambda: True
        return lambda: kernel32.WaitForSingleObject(handle, 0) == 0
    original = os.getppid()
    return lambda: os.getppid() != original


async def run_proxy(config, stop_file=None, ready_file=None, max_lifetime=None, parent_pid=None):
    proxy = EgressProxy(config)
    await proxy.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    def request_stop(*_):
        loop.call_soon_threadsafe(stop.set)

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, request_stop)
            except (ValueError, OSError):
                pass

    if ready_file:
        tmp = ready_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"pid": os.getpid(), "host": config.listen_host, "port": proxy.bound_port}, fh)
        os.replace(tmp, ready_file)

    parent_gone = _parent_watch_factory(parent_pid)
    began = time.monotonic()
    try:
        while not stop.is_set():
            if stop_file and os.path.exists(stop_file):
                break
            if max_lifetime is not None and time.monotonic() - began >= max_lifetime:
                break
            if parent_gone is not None and parent_gone():
                break
            try:
                await asyncio.wait_for(stop.wait(), 0.25)
            except asyncio.TimeoutError:
                pass
    finally:
        await proxy.stop()


def main(argv=None):
    ap = argparse.ArgumentParser(description="Voidseal host HTTPS CONNECT allowlist proxy.")
    ap.add_argument("--listen-host", required=True, help="the gateway IP to bind (never 0.0.0.0)")
    ap.add_argument("--listen-port", required=True, type=int)
    ap.add_argument("--allow", action="append", default=[], help="an allowed name, *.suffix or IP literal; repeat")
    ap.add_argument("--log", default=None, help="append one JSON line per connection here")
    ap.add_argument("--stop-file", default=None, help="exit cleanly once this file exists")
    ap.add_argument("--ready-file", default=None, help="written (pid, host, port) once listening")
    ap.add_argument("--max-connections", type=int, default=64)
    ap.add_argument("--header-timeout", type=float, default=10.0)
    ap.add_argument("--connect-timeout", type=float, default=10.0)
    ap.add_argument("--idle-timeout", type=float, default=120.0)
    ap.add_argument("--total-timeout", type=float, default=3600.0)
    ap.add_argument("--bind-retry-seconds", type=float, default=15.0)
    ap.add_argument("--max-lifetime-seconds", type=float, default=None)
    ap.add_argument("--parent-pid", type=int, default=None)
    ap.add_argument("--client", default=None,
                    help="the one peer address served (the guest's IP); any other peer is closed at once")
    args = ap.parse_args(argv)

    try:
        config = ProxyConfig(
            listen_host=args.listen_host, listen_port=args.listen_port, allowlist=Allowlist(args.allow),
            log_path=args.log, max_connections=args.max_connections, header_timeout=args.header_timeout,
            connect_timeout=args.connect_timeout, idle_timeout=args.idle_timeout,
            total_timeout=args.total_timeout, bind_retry_seconds=args.bind_retry_seconds,
            client_ip=args.client)
    except ValueError as exc:
        print("voidseal-egress-proxy: configuration refused: %s" % exc, file=sys.stderr)
        return 2
    try:
        asyncio.run(run_proxy(config, stop_file=args.stop_file, ready_file=args.ready_file,
                              max_lifetime=args.max_lifetime_seconds, parent_pid=args.parent_pid))
    except OSError as exc:
        print("voidseal-egress-proxy: could not listen on %s:%s: %s" % (args.listen_host, args.listen_port, exc),
              file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
