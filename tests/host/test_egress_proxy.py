# tests/host/test_egress_proxy.py
"""Tests for scripts/egress/voidseal_egress_proxy.py, the host CONNECT allowlist proxy.

Everything runs on loopback sockets with a stub resolver and a stub connector injected, so no test
touches real DNS or the internet. The stub connector ignores the address the proxy chose and connects
to a loopback echo server; it records the (ip, port) the proxy asked for so a test can prove which
address was picked. Public-looking stub addresses (93.184.216.34 and friends) are never dialled.
"""
import asyncio
import ipaddress
import json
import pathlib
import subprocess
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "egress"))
import voidseal_egress_proxy as vp  # noqa: E402

PUBLIC_A = "93.184.216.34"
PUBLIC_B = "151.101.1.1"
PUBLIC_V6 = "2606:4700::6810:84e5"


# --------------------------------------------------------------------------------------------------
# harness
# --------------------------------------------------------------------------------------------------
class Harness:
    def __init__(self, tmp_path, allow, resolve_map=None, **cfg):
        self.log = tmp_path / "egress.log"
        self.resolve_map = resolve_map or {}
        self.resolve_calls = []
        self.connect_calls = []
        self.allow = allow
        self.cfg = cfg
        self.echo_server = None
        self.proxy = None

    async def _echo(self, reader, writer):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()

    async def resolver(self, name):
        self.resolve_calls.append(name)
        value = self.resolve_map.get(name)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise OSError("stub: no such name")
        return list(value)

    async def connector(self, ip, port):
        self.connect_calls.append((ip, port))
        host, eport = self.echo_server.sockets[0].getsockname()[:2]
        return await asyncio.open_connection(host, eport)

    async def __aenter__(self):
        self.echo_server = await asyncio.start_server(self._echo, "127.0.0.1", 0)
        config = vp.ProxyConfig(
            listen_host="127.0.0.1",
            listen_port=0,
            allowlist=vp.Allowlist(self.allow),
            log_path=str(self.log),
            **self.cfg,
        )
        self.proxy = vp.EgressProxy(config, resolver=self.resolver, connector=self.connector)
        await self.proxy.start()
        return self

    async def __aexit__(self, *exc):
        await self.proxy.stop()
        self.echo_server.close()
        await self.echo_server.wait_closed()

    async def open(self):
        return await asyncio.open_connection("127.0.0.1", self.proxy.bound_port)

    async def request(self, raw, read_timeout=3.0):
        """Send raw bytes, return (status, head_bytes, reader, writer)."""
        reader, writer = await self.open()
        writer.write(raw)
        await writer.drain()
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), read_timeout)
        status = int(head.split(b" ", 2)[1])
        return status, head, reader, writer

    def log_lines(self):
        if not self.log.exists():
            return []
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines() if line.strip()]


def connect_req(target, version="HTTP/1.1", extra=b""):
    t = target.encode()
    return b"CONNECT " + t + b" " + version.encode() + b"\r\nHost: " + t + b"\r\n" + extra + b"\r\n"


def run(coro):
    return asyncio.run(coro)


async def close(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass


async def wait_for_log(h, count, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        lines = h.log_lines()
        if len(lines) >= count:
            return lines
        await asyncio.sleep(0.02)
    return h.log_lines()


async def status_of(tmp_path, allow, target, resolve_map=None, **cfg):
    async with Harness(tmp_path, allow, resolve_map, **cfg) as h:
        status, _, _, w = await h.request(connect_req(target))
        await close(w)
        lines = await wait_for_log(h, 1)
        return status, lines, h


# --------------------------------------------------------------------------------------------------
# allowlist parsing and matching (pure)
# --------------------------------------------------------------------------------------------------
def test_allowlist_exact_names_are_case_insensitive_and_ignore_a_trailing_dot():
    al = vp.Allowlist(["API.Example.com"])
    assert al.match_name("api.example.com")
    assert al.match_name(vp.normalize_name("API.EXAMPLE.COM."))
    assert not al.match_name("example.com")
    assert not al.match_name("xapi.example.com")


def test_allowlist_suffix_rules_match_subdomains_only():
    al = vp.Allowlist(["*.cdn.example.com"])
    assert al.match_name("a.cdn.example.com")
    assert al.match_name("a.b.cdn.example.com")
    assert not al.match_name("cdn.example.com"), "a *. rule names subdomains, not the suffix itself"
    assert not al.match_name("badcdn.example.com"), "a suffix rule must match on a label boundary"
    assert not al.match_name("cdn.example.com.evil.test")


def test_allowlist_idna_entries_and_requests_meet_in_ascii_form():
    al = vp.Allowlist(["bücher.example"])
    assert al.match_name("xn--bcher-kva.example")
    assert al.match_name(vp.normalize_name("BÜCHER.example"))
    al2 = vp.Allowlist(["xn--bcher-kva.example"])
    assert al2.match_name(vp.normalize_name("bücher.example"))


@pytest.mark.parametrize("bad", ["", "*.", "*.com", "a b.example", "exa_mple.com", "-lead.example.com",
                                 "http://example.com", "example.com/path", "*example.com", "a..b.example",
                                 "x" * 64 + ".example.com", "*.*.example.com", "10.0.0.1/8", "1234",
                                 "example.123"])
def test_allowlist_refuses_malformed_or_overbroad_entries(bad):
    with pytest.raises(ValueError):
        vp.Allowlist([bad])


def test_allowlist_refuses_an_empty_list():
    with pytest.raises(ValueError):
        vp.Allowlist([])


def test_ip_literals_match_only_when_listed():
    al = vp.Allowlist(["example.com", PUBLIC_A, "[" + PUBLIC_V6 + "]"])
    assert al.match_ip(ipaddress.ip_address(PUBLIC_A))
    assert al.match_ip(ipaddress.ip_address(PUBLIC_V6))
    assert not al.match_ip(ipaddress.ip_address(PUBLIC_B))


@pytest.mark.parametrize("addr,code", [
    ("10.0.0.5", "private"), ("192.168.1.1", "private"), ("172.16.0.1", "private"),
    ("127.0.0.1", "loopback"), ("169.254.169.254", "link-local"), ("224.0.0.1", "multicast"),
    ("0.0.0.0", "unspecified"), ("240.0.0.1", "reserved"), ("100.64.0.1", "non-global"),
    ("::1", "loopback"), ("fe80::1", "link-local"), ("ff02::1", "multicast"), ("::", "unspecified"),
    ("fc00::1", "private"), ("::ffff:10.0.0.1", "private"), ("::ffff:127.0.0.1", "loopback"),
    ("2002:0a00:0001::1", "private"),
])
def test_forbidden_address_classes(addr, code):
    assert vp.forbidden_reason(ipaddress.ip_address(addr)) == code


@pytest.mark.parametrize("addr", [PUBLIC_A, PUBLIC_B, PUBLIC_V6])
def test_public_addresses_are_permitted(addr):
    assert vp.forbidden_reason(ipaddress.ip_address(addr)) is None


# --------------------------------------------------------------------------------------------------
# end to end on loopback
# --------------------------------------------------------------------------------------------------
def test_allowed_name_tunnels_bytes_both_ways_and_logs_counts(tmp_path):
    async def body():
        async with Harness(tmp_path, ["api.example.com"], {"api.example.com": [PUBLIC_A]}) as h:
            status, head, reader, writer = await h.request(connect_req("api.example.com:443"))
            assert status == 200
            assert head.startswith(b"HTTP/1.1 200 ")
            writer.write(b"ping-through-tunnel")
            await writer.drain()
            echoed = await asyncio.wait_for(reader.readexactly(len(b"ping-through-tunnel")), 3)
            assert echoed == b"ping-through-tunnel"
            await close(writer)
            lines = await wait_for_log(h, 1)
            assert h.connect_calls == [(PUBLIC_A, 443)], "the proxy dials the address it resolved, never the name"
            assert len(lines) == 1
            rec = lines[0]
            assert rec["decision"] == "allow" and rec["reason"] == "tunnel-closed"
            assert rec["target"] == "api.example.com" and rec["port"] == 443
            assert rec["upstream_ip"] == PUBLIC_A
            assert rec["bytes_up"] == len(b"ping-through-tunnel")
            assert rec["bytes_down"] == len(b"ping-through-tunnel")
            for key in ("ts", "client", "status", "duration_ms"):
                assert key in rec
    run(body())


def test_denied_name_gets_403_and_is_never_resolved(tmp_path):
    status, lines, h = run(status_of(tmp_path, ["api.example.com"], "evil.example.net:443",
                                     {"evil.example.net": [PUBLIC_A]}))
    assert status == 403
    assert h.resolve_calls == [], "a name off the allowlist must not even be resolved"
    assert h.connect_calls == []
    assert lines[0]["decision"] == "deny" and lines[0]["reason"] == "not-allowlisted"


def test_suffix_rule_allows_a_subdomain_end_to_end(tmp_path):
    status, _, _ = run(status_of(tmp_path, ["*.files.example.com"], "a.files.example.com:443",
                                 {"a.files.example.com": [PUBLIC_A]}))
    assert status == 200


def test_suffix_rule_does_not_allow_the_bare_suffix_end_to_end(tmp_path):
    status, lines, _ = run(status_of(tmp_path, ["*.files.example.com"], "files.example.com:443",
                                     {"files.example.com": [PUBLIC_A]}))
    assert status == 403
    assert lines[0]["reason"] == "not-allowlisted"


def test_requested_name_is_matched_case_insensitively(tmp_path):
    status, lines, h = run(status_of(tmp_path, ["api.example.com"], "API.Example.COM:443",
                                     {"api.example.com": [PUBLIC_A]}))
    assert status == 200
    assert h.resolve_calls == ["api.example.com"], "the proxy resolves the normalized name"
    assert lines[0]["target"] == "api.example.com"


def test_idna_request_matches_unicode_allowlist_entry(tmp_path):
    status, _, h = run(status_of(tmp_path, ["bücher.example"], "xn--bcher-kva.example:443",
                                 {"xn--bcher-kva.example": [PUBLIC_A]}))
    assert status == 200
    assert h.resolve_calls == ["xn--bcher-kva.example"]


def test_unlisted_ip_literal_is_denied_without_dialing(tmp_path):
    status, lines, h = run(status_of(tmp_path, ["api.example.com"], PUBLIC_A + ":443"))
    assert status == 403
    assert h.connect_calls == []
    assert lines[0]["reason"] == "ip-literal-not-allowlisted"


def test_listed_public_ip_literal_is_allowed(tmp_path):
    status, _, h = run(status_of(tmp_path, [PUBLIC_A], PUBLIC_A + ":443"))
    assert status == 200
    assert h.resolve_calls == [], "an IP literal needs no resolution"
    assert h.connect_calls == [(PUBLIC_A, 443)]


def test_listed_private_ip_literal_is_still_refused(tmp_path):
    status, lines, h = run(status_of(tmp_path, ["10.1.2.3"], "10.1.2.3:443"))
    assert status == 403
    assert h.connect_calls == []
    assert lines[0]["reason"] == "forbidden-address"
    assert lines[0]["address_class"] == "private"


def test_bracketed_ipv6_literal_is_parsed_and_denied_when_unlisted(tmp_path):
    status, lines, _ = run(status_of(tmp_path, ["api.example.com"], "[" + PUBLIC_V6 + "]:443"))
    assert status == 403
    assert lines[0]["reason"] == "ip-literal-not-allowlisted"


def test_numeric_host_forms_are_not_names(tmp_path):
    # 2130706433 is 127.0.0.1 in a form getaddrinfo accepts; it must never be treated as a hostname.
    status, lines, h = run(status_of(tmp_path, ["api.example.com"], "2130706433:443"))
    assert status == 400
    assert h.resolve_calls == []
    assert lines[0]["reason"] == "malformed-host"


@pytest.mark.parametrize("answer,klass", [
    (["10.0.0.7"], "private"),
    (["127.0.0.1"], "loopback"),
    (["169.254.169.254"], "link-local"),
    (["::1"], "loopback"),
    (["fe80::1"], "link-local"),
    (["ff02::1"], "multicast"),
    (["0.0.0.0"], "unspecified"),
    (["240.0.0.9"], "reserved"),
    ([PUBLIC_A, "192.168.0.10"], "private"),
])
def test_dns_rebinding_answers_with_a_forbidden_address_are_refused(tmp_path, answer, klass):
    status, lines, h = run(status_of(tmp_path, ["api.example.com"], "api.example.com:443",
                                     {"api.example.com": answer}))
    assert status == 403
    assert h.connect_calls == [], "no address from a poisoned answer may be dialled, not even the public one"
    assert lines[0]["reason"] == "forbidden-address"
    assert lines[0]["address_class"] == klass


def test_resolution_failure_is_502_and_nothing_is_dialled(tmp_path):
    status, lines, h = run(status_of(tmp_path, ["api.example.com"], "api.example.com:443",
                                     {"api.example.com": OSError("stub NXDOMAIN")}))
    assert status == 502
    assert h.connect_calls == []
    assert lines[0]["reason"] == "resolve-failed"


def test_empty_resolution_is_502(tmp_path):
    status, lines, _ = run(status_of(tmp_path, ["api.example.com"], "api.example.com:443",
                                     {"api.example.com": []}))
    assert status == 502
    assert lines[0]["reason"] == "resolve-failed"


def test_connect_failure_falls_through_to_the_next_address_then_502(tmp_path):
    async def body():
        async with Harness(tmp_path, ["api.example.com"], {"api.example.com": [PUBLIC_A, PUBLIC_B]}) as h:
            real = h.connector

            async def flaky(ip, port):
                if ip == PUBLIC_A:
                    h.connect_calls.append((ip, port))
                    raise ConnectionRefusedError("stub refused")
                return await real(ip, port)
            h.proxy._connector = flaky
            status, _, _, w = await h.request(connect_req("api.example.com:443"))
            assert status == 200
            assert h.connect_calls == [(PUBLIC_A, 443), (PUBLIC_B, 443)]
            await close(w)

            async def dead(ip, port):
                raise ConnectionRefusedError("stub refused")
            h.proxy._connector = dead
            status, _, _, w = await h.request(connect_req("api.example.com:443"))
            assert status == 502
            await close(w)
            lines = await wait_for_log(h, 2)
            assert lines[-1]["reason"] == "connect-failed"
    run(body())


@pytest.mark.parametrize("raw", [
    b"GET http://api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
    b"POST http://api.example.com/x HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
    b"connect api.example.com:443 HTTP/1.1\r\n\r\n",
    b"OPTIONS * HTTP/1.1\r\n\r\n",
])
def test_non_connect_methods_get_405_with_an_allow_header(tmp_path, raw):
    async def body():
        async with Harness(tmp_path, ["api.example.com"], {"api.example.com": [PUBLIC_A]}) as h:
            status, head, _, w = await h.request(raw)
            await close(w)
            assert status == 405
            assert b"\r\nAllow: CONNECT\r\n" in head
            assert h.resolve_calls == [] and h.connect_calls == []
            lines = await wait_for_log(h, 1)
            assert lines[0]["reason"] == "method-not-allowed"
            assert lines[0]["target"] is None, "a non-CONNECT target (possibly a URL with a query) is never logged"
    run(body())


@pytest.mark.parametrize("raw,reason", [
    (b"CONNECT api.example.com HTTP/1.1\r\n\r\n", "malformed-target"),
    (b"CONNECT api.example.com:https HTTP/1.1\r\n\r\n", "malformed-target"),
    (b"CONNECT api.example.com:443 HTTP/2.0\r\n\r\n", "bad-version"),
    (b"CONNECT api.example.com:443\r\n\r\n", "malformed-request-line"),
    (b"CONNECT  api.example.com:443 HTTP/1.1\r\n\r\n", "malformed-request-line"),
    (b"CONNECT api.example.com:443 HTTP/1.1 extra\r\n\r\n", "malformed-request-line"),
    (b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\r\n\r\n", "malformed-request"),
    (b"CONNECT api.exa_mple.com:443 HTTP/1.1\r\n\r\n", "malformed-host"),
    (b"CONNECT [::1:443 HTTP/1.1\r\n\r\n", "malformed-host"),
    (b"CONNECT api.example.com:443 HTTP/1.1\r\nno-colon-header\r\n\r\n", "malformed-header"),
    (b"CONNECT api.example.com:443 HTTP/1.1\r\n folded: x\r\n\r\n", "malformed-header"),
    (b"CONNECT api.example.com:443 HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello", "request-body"),
    (b"CONNECT api.example.com:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", "request-body"),
    (b"CONNECT api.example.com:443 HTTP/1.1\r\nX: caf\xc3\xa9\r\n\r\n", "malformed-request"),
])
def test_malformed_requests_get_400(tmp_path, raw, reason):
    async def body():
        async with Harness(tmp_path, ["api.example.com"], {"api.example.com": [PUBLIC_A]}) as h:
            status, _, _, w = await h.request(raw)
            await close(w)
            assert status == 400
            assert h.connect_calls == []
            lines = await wait_for_log(h, 1)
            assert lines[0]["reason"] == reason
    run(body())


@pytest.mark.parametrize("port", ["80", "8443", "22", "0", "65535", "4430", "0443"])
def test_ports_other_than_443_are_refused(tmp_path, port):
    status, lines, h = run(status_of(tmp_path, ["api.example.com"], "api.example.com:" + port,
                                     {"api.example.com": [PUBLIC_A]}))
    assert status == 403
    assert h.resolve_calls == [] and h.connect_calls == []
    assert lines[0]["reason"] == "port-not-allowed"


def test_http_1_0_connect_is_accepted(tmp_path):
    async def body():
        async with Harness(tmp_path, ["api.example.com"], {"api.example.com": [PUBLIC_A]}) as h:
            status, _, _, w = await h.request(connect_req("api.example.com:443", version="HTTP/1.0"))
            await close(w)
            assert status == 200
    run(body())


def test_oversized_header_block_gets_431(tmp_path):
    async def body():
        async with Harness(tmp_path, ["api.example.com"], {"api.example.com": [PUBLIC_A]},
                           max_header_bytes=1024) as h:
            big = b"X-Pad: " + b"a" * 4096 + b"\r\n"
            status, _, _, w = await h.request(connect_req("api.example.com:443", extra=big))
            await close(w)
            assert status == 431
            lines = await wait_for_log(h, 1)
            assert lines[0]["reason"] == "header-too-large"
    run(body())


def test_header_line_flood_gets_431(tmp_path):
    async def body():
        async with Harness(tmp_path, ["api.example.com"], {"api.example.com": [PUBLIC_A]},
                           max_header_lines=8) as h:
            flood = b"".join(b"X-H%d: v\r\n" % i for i in range(20))
            status, _, _, w = await h.request(connect_req("api.example.com:443", extra=flood))
            await close(w)
            assert status == 431
            lines = await wait_for_log(h, 1)
            assert lines[0]["reason"] == "too-many-headers"
    run(body())


def test_silent_client_is_dropped_after_the_header_timeout(tmp_path):
    async def body():
        async with Harness(tmp_path, ["api.example.com"], {}, header_timeout=0.3) as h:
            reader, writer = await h.open()
            writer.write(b"CONNECT api.exa")  # never finishes the head
            await writer.drain()
            data = await asyncio.wait_for(reader.read(), 3)
            assert data == b"", "the proxy closes without a response once the header deadline passes"
            await close(writer)
            lines = await wait_for_log(h, 1)
            assert lines[0]["reason"] == "header-timeout"
            assert lines[0]["target"] is None
    run(body())


def test_connection_cap_refuses_the_extra_connection_with_503(tmp_path):
    async def body():
        async with Harness(tmp_path, ["api.example.com"], {"api.example.com": [PUBLIC_A]},
                           max_connections=1) as h:
            status, _, _, w1 = await h.request(connect_req("api.example.com:443"))
            assert status == 200
            status2, _, _, w2 = await h.request(connect_req("api.example.com:443"))
            assert status2 == 503
            await close(w2)
            await close(w1)
            lines = await wait_for_log(h, 2)
            assert any(rec["reason"] == "connection-cap" for rec in lines)
            # the slot frees up once the first tunnel closes
            await asyncio.sleep(0.2)
            status3, _, _, w3 = await h.request(connect_req("api.example.com:443"))
            assert status3 == 200
            await close(w3)
    run(body())


def test_idle_tunnel_is_closed_after_the_idle_timeout(tmp_path):
    async def body():
        async with Harness(tmp_path, ["api.example.com"], {"api.example.com": [PUBLIC_A]},
                           idle_timeout=0.3, total_timeout=30) as h:
            status, _, reader, writer = await h.request(connect_req("api.example.com:443"))
            assert status == 200
            started = time.monotonic()
            data = await asyncio.wait_for(reader.read(), 5)
            assert data == b""
            assert time.monotonic() - started < 4
            await close(writer)
            lines = await wait_for_log(h, 1)
            assert lines[0]["reason"] == "idle-timeout"
    run(body())


def test_busy_tunnel_is_closed_at_the_total_timeout(tmp_path):
    async def body():
        async with Harness(tmp_path, ["api.example.com"], {"api.example.com": [PUBLIC_A]},
                           idle_timeout=5, total_timeout=0.6) as h:
            status, _, reader, writer = await h.request(connect_req("api.example.com:443"))
            assert status == 200
            closed = False
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    writer.write(b"x")
                    await writer.drain()
                    chunk = await asyncio.wait_for(reader.read(16), 1)
                except (ConnectionError, OSError):
                    closed = True
                    break
                if chunk == b"":
                    closed = True
                    break
                await asyncio.sleep(0.05)
            assert closed, "the total deadline must end a tunnel that never goes idle"
            await close(writer)
            lines = await wait_for_log(h, 1)
            assert lines[0]["reason"] == "total-timeout"
    run(body())


def test_log_never_contains_payload_bytes(tmp_path):
    secret = b"SECRET-PAYLOAD-7f3a9c"

    async def body():
        async with Harness(tmp_path, ["api.example.com"], {"api.example.com": [PUBLIC_A]}) as h:
            status, _, reader, writer = await h.request(connect_req("api.example.com:443"))
            assert status == 200
            writer.write(secret)
            await writer.drain()
            await asyncio.wait_for(reader.readexactly(len(secret)), 3)
            await close(writer)
            # a denied request carrying the secret in a header, and a GET carrying it in the URL
            s2, _, _, w2 = await h.request(connect_req("evil.example.net:443", extra=b"X-Leak: " + secret + b"\r\n"))
            await close(w2)
            s3, _, _, w3 = await h.request(b"GET http://api.example.com/?q=" + secret + b" HTTP/1.1\r\n\r\n")
            await close(w3)
            assert (s2, s3) == (403, 405)
            await wait_for_log(h, 3)
    run(body())
    text = (tmp_path / "egress.log").read_text(encoding="utf-8")
    assert len(text.splitlines()) == 3, "exactly one JSON line per connection"
    assert secret.decode() not in text


def test_stop_ends_open_tunnels_and_logs_them(tmp_path):
    async def body():
        h = Harness(tmp_path, ["api.example.com"], {"api.example.com": [PUBLIC_A]})
        await h.__aenter__()
        status, _, reader, writer = await h.request(connect_req("api.example.com:443"))
        assert status == 200
        await h.__aexit__(None, None, None)
        data = await asyncio.wait_for(reader.read(), 3)
        assert data == b""
        await close(writer)
        lines = h.log_lines()
        assert len(lines) == 1 and lines[0]["reason"] == "shutdown"
    run(body())


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "", "localhost"])
def test_refuses_an_unspecified_or_non_literal_listen_address(host):
    with pytest.raises(ValueError):
        vp.ProxyConfig(listen_host=host, listen_port=13128, allowlist=vp.Allowlist(["api.example.com"]),
                       log_path=None)


# --------------------------------------------------------------------------------------------------
# the command line: ready file, stop file, config errors (a real child process on loopback)
# --------------------------------------------------------------------------------------------------
def _spawn(tmp_path, *extra):
    args = [sys.executable, str(ROOT / "scripts" / "egress" / "voidseal_egress_proxy.py"),
            "--listen-host", "127.0.0.1", "--listen-port", "0",
            "--log", str(tmp_path / "cli.log"),
            "--stop-file", str(tmp_path / "stop"),
            "--ready-file", str(tmp_path / "ready.json")]
    return subprocess.Popen(args + list(extra), stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def test_cli_writes_a_ready_file_and_exits_cleanly_on_the_stop_file(tmp_path):
    proc = _spawn(tmp_path, "--allow", "api.example.com", "--allow", "*.files.example.com")
    try:
        deadline = time.monotonic() + 15
        while not (tmp_path / "ready.json").exists() and time.monotonic() < deadline:
            assert proc.poll() is None, proc.stderr.read().decode()
            time.sleep(0.05)
        ready = json.loads((tmp_path / "ready.json").read_text(encoding="utf-8"))
        assert ready["pid"] == proc.pid
        assert ready["host"] == "127.0.0.1" and ready["port"] > 0
        (tmp_path / "stop").write_text("stop", encoding="utf-8")
        assert proc.wait(timeout=15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()


def test_cli_exits_at_the_maximum_lifetime(tmp_path):
    proc = _spawn(tmp_path, "--allow", "api.example.com", "--max-lifetime-seconds", "1")
    try:
        assert proc.wait(timeout=15) == 0
    finally:
        if proc.poll() is None:
            proc.kill()


@pytest.mark.parametrize("extra", [
    [],                                              # no allowlist at all
    ["--allow", "*.com"],                            # over-broad suffix
    ["--allow", "bad name"],                         # malformed
])
def test_cli_refuses_a_bad_allowlist_with_exit_2(tmp_path, extra):
    proc = _spawn(tmp_path, *extra)
    try:
        assert proc.wait(timeout=15) == 2
        assert not (tmp_path / "ready.json").exists()
    finally:
        if proc.poll() is None:
            proc.kill()
