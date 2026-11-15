#!/usr/bin/env python3
"""
upstream-resolver.py — host-side wildcard resolver for the opencode-sandbox
egress fence.

Runs in the HOST's network namespace (the fence wrapper starts it before
pasta). The in-netns agent (fence-agent.py) forwards wildcard lookups over
the unix socket <dir>/upstream.sock; this process answers them with the
host's own resolver, but ONLY for names that are strict subdomains of the
allowlist's wildcard bases (<dir>/wildcards.txt, one `*.domain` per line)
and not denied (<dir>/denied.txt: deniedDomains, which take precedence).
Anything else gets REFUSED (rcode 2) or, when denied, NXDOMAIN (rcode 3) —
never an answer: a malicious guest can use this channel for no more than
what the proxy model already allows for the same entries. The fence is
IPv4-only, so AAAA requests are answered empty.

Protocol: one line each way over the unix stream socket.
    request:  <name> <qtype>\\n            (qtype: 1 = A, 28 = AAAA)
    reply:    <rcode>\\t<ip> [<ip> ...]\\n
              rcode: 0 = answered (the family may legitimately be empty),
                     2 = refused / not resolvable (SERVFAIL),
                     3 = name does not exist (NXDOMAIN)
Resolutions are cached for the daemon's lifetime (the command's lifetime)
and new ones are capped, so the channel cannot be farmed for lookups. The daemon
exits on SIGTERM/SIGINT (the fence wrapper kills it after pasta, the plugin
on the shell "ended" event).
"""
import os
import re
import signal
import socket
import struct
import sys

MAX_RESOLUTIONS = 512
HOSTNAME_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$"
)


def load_bases(path):
    """Wildcard bases, one per line as `*.domain`; unparseable lines drop."""
    bases = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("*.") and HOSTNAME_RE.match(line[2:]):
                    bases.append(line[2:].lower())
    except OSError:
        pass
    return bases


def matches(name, bases):
    """Strict subdomain of an allowed base (the base itself is not a match)."""
    return any(
        name.endswith("." + b) and name.count(".") > b.count(".") for b in bases
    )


def load_denied(path):
    """deniedDomains as written by the fence (<dir>/denied.txt): `*` denies
    every name, `*.domain` denies strict subdomains, anything else is an exact
    name. Returns (deny_all, names, suffixes)."""
    deny_all, names, suffixes = False, set(), []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip().lower()
                if line == "*":
                    deny_all = True
                elif line.startswith("*."):
                    suffixes.append(line[1:])
                elif line:
                    names.add(line)
    except OSError:
        pass
    return deny_all, names, suffixes


def is_denied(name, denied):
    """Denials take precedence over the wildcard allowlist."""
    deny_all, names, suffixes = denied
    return deny_all or name in names or any(name.endswith(s) for s in suffixes)


def peer_uid(conn):
    """SO_PEERCRED uid (Linux); None when not available. The buffer size must
    be passed explicitly (SO_PEERCRED is a 12-byte struct ucred), else
    getsockopt() may return a bare int and struct.unpack() would raise."""
    try:
        cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3I"))
        return struct.unpack("3I", cred)[1]
    except (OSError, TypeError, struct.error):
        return None


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    d = sys.argv[1]
    bases = load_bases(os.path.join(d, "wildcards.txt"))
    denied = load_denied(os.path.join(d, "denied.txt"))
    sock_path = os.path.join(d, "upstream.sock")
    try:
        os.unlink(sock_path)
    except OSError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(sock_path)
    s.listen(1)
    s.settimeout(1.0)
    sys.stderr.write(f"upstream listening on {sock_path}\n")
    sys.stderr.flush()
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *a: sys.exit(0))
    cache = {}
    resolved = 0
    while True:
        try:
            conn, _ = s.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            if peer_uid(conn) != os.getuid():
                continue  # not our fence: no channel
            rfile = conn.makefile("rb")
            while True:
                line = rfile.readline()
                if not line:
                    break
                parts = line.strip().split()
                name = parts[0].decode("ascii", "replace").lower() if parts else ""
                qtype = parts[1].decode("ascii", "replace") if len(parts) > 1 else ""
                if qtype not in ("1", "28") or not HOSTNAME_RE.match(name) or not matches(name, bases):
                    conn.sendall(b"2\t\n")  # refused
                    continue
                if is_denied(name, denied):
                    conn.sendall(b"3\t\n")  # denied: as if it did not exist
                    continue
                if qtype == "28":
                    # The fence is IPv4-only: no AAAA answers (an unusable v6
                    # address only makes clients try, fail, and fall back).
                    conn.sendall(b"0\t\n")
                    continue
                if name not in cache:
                    if resolved >= MAX_RESOLUTIONS:
                        conn.sendall(b"2\t\n")  # cap reached: no new lookups
                        continue
                    resolved += 1
                    try:
                        infos = socket.getaddrinfo(name, None, socket.AF_INET)
                        v4 = sorted({i[4][0] for i in infos if i[0] == socket.AF_INET})
                        cache[name] = (0, v4)
                    except socket.gaierror as err:
                        cache[name] = (3 if err.errno == socket.EAI_NONAME else 2, [])
                    except OSError:
                        cache[name] = (2, [])
                rcode, ips = cache[name]
                conn.sendall(f"{rcode}\t{' '.join(ips)}\n".encode())
        except (OSError, UnicodeError):
            pass
        finally:
            conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
