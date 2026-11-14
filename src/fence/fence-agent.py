#!/usr/bin/env python3
"""
fence-agent.py — in-netns rule writer for the opencode-sandbox egress fence.

Runs in the GUEST (pasta) network namespace, started by guest.sh when the
allowlist carries wildcard entries. The pinned responder (in its own netns,
same host mount namespace) forwards wildcard lookups over <dir>/agent.sock;
the agent vouches each one with the host-side upstream resolver
(<dir>/upstream.sock) and, for every new allowed address, adds an accept
rule to the egress ruleset in THIS netns. The name gate stays the single
entry: only addresses the upstream resolver answered for an allowed
wildcard ever get a rule.

Protocol: one line each way, same shape as upstream-resolver.py:
    <name> <qtype>\\n   ->   <rcode>\\t<ip> [<ip> ...]\\n
    rcode: 0 = answered, 2 = refused/SERVFAIL, 3 = NXDOMAIN
Rules are added at most once per address. Exits on SIGTERM/SIGINT (guest.sh
kills it in its cleanup and fail paths).
"""
import os
import signal
import socket
import struct
import subprocess
import sys

# Must match the fence's nft.rules (written by buildFenceCommand).
CHAIN = ("inet", "egress", "output")
QUERY_TIMEOUT = 3.0


def query_upstream(sock_path, name, qtype):
    """One request to the host-side resolver. (2, []) when it is not there."""
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(QUERY_TIMEOUT)
        conn.connect(sock_path)
        conn.sendall(f"{name} {qtype}\n".encode())
        line = conn.makefile("rb").readline()
        conn.close()
        parts = line.decode().strip().split("\t")
        if not parts:
            # Upstream closed without answering (should not happen): fail closed.
            return 2, []
        return int(parts[0]), (parts[1].split() if len(parts) > 1 else [])
    except (OSError, ValueError):
        return 2, []


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    d = sys.argv[1]
    sock_path = os.path.join(d, "agent.sock")
    upstream = os.path.join(d, "upstream.sock")
    try:
        os.unlink(sock_path)
    except OSError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(sock_path)
    s.listen(1)
    s.settimeout(1.0)
    sys.stderr.write(f"agent listening on {sock_path}\n")
    sys.stderr.flush()
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *a: sys.exit(0))
    added = set()
    while True:
        try:
            conn, _ = s.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            # The responder is our only client; same user namespace => same uid.
            # SO_PEERCRED is a 12-byte struct ucred: the buffer size must be
            # passed explicitly, else getsockopt() may return a bare int and
            # struct.unpack() would raise (crashing the whole vouch path).
            try:
                cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3I"))
                uid = struct.unpack("3I", cred)[1]
            except (OSError, TypeError, struct.error):
                uid = None
            if uid != os.getuid():
                continue
            rfile = conn.makefile("rb")
            while True:
                line = rfile.readline()
                if not line:
                    break
                parts = line.strip().split()
                name = parts[0].decode("ascii", "replace") if parts else ""
                # qtype must be a str: it is re-serialized into the upstream
                # request line, so a leftover bytes (b"1") would corrupt it
                # into the literal text "b'1'".
                qtype = parts[1].decode("ascii", "replace") if len(parts) > 1 else ""
                rcode, ips = query_upstream(upstream, name, qtype)
                if rcode == 0:
                    for ip in ips:
                        if ip in added:
                            continue
                        stmt = "ip" if ":" not in ip else "ip6"
                        proc = subprocess.run(
                            ["nft", "add", "rule", *CHAIN, f"{stmt} daddr", ip, "accept"],
                            capture_output=True,
                        )
                        if proc.returncode != 0:
                            rcode, ips = 2, []  # the backstop wins: no address, no rule
                            break
                        added.add(ip)
                conn.sendall(f"{rcode}\t{' '.join(ips)}\n".encode())
        except (OSError, UnicodeError):
            pass
        finally:
            conn.close()
    try:
        os.unlink(sock_path)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
