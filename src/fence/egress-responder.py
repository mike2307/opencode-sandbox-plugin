#!/usr/bin/env python3
"""
egress-responder.py — minimal in-netns DNS pinning responder (opencode-sandbox
fence asset).

A deliberately tiny UDP DNS server that answers ONLY what a pin file says and
NXDOMAINs everything else. No privilege drop, no upstream, no daemon.

  usage:  egress-responder.py <port> <pinfile> [addr]
    pinfile: one allowed name per line ->
                <name> <ip> [<ip> ...]
          (a name absent from the pin file is sinkholed with NXDOMAIN). This is
           the NAME gate of the egress model.

Only A (1) and AAAA (28) queries are answered. Pinned names are answered from
the pin file. Non-pinned names that are strict subdomains of a wildcard base
(<dir>/wildcards.txt, next to the pin file) and not denied (<dir>/denied.txt)
are vouched on demand through the fence agent (unix socket <dir>/agent.sock) — which asks the host-side upstream
resolver and opens the egress ruleset for the answered addresses — anything
else is NXDOMAIN. Single-question queries only (which is what resolvers send).
"""
import os
import re
import socket
import struct
import sys


def parse_question(pkt: bytes):
    """Return (tid, qname, qtype, question_bytes). question_bytes starts at
    offset 12 (the QNAME) so it can be echoed back verbatim."""
    tid = pkt[0:2]
    if len(pkt) < 12:
        raise ValueError("short")
    qdcount = struct.unpack(">H", pkt[4:6])[0]
    if qdcount == 0:
        raise ValueError("no question")
    off = 12
    labels = []
    while True:
        ln = pkt[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0:  # compression pointer in a query question is unexpected
            raise ValueError("pointer in question")
        labels.append(pkt[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    qname = ".".join(labels).lower()
    qtype = struct.unpack(">H", pkt[off:off + 2])[0]
    question = pkt[12:off + 4]
    return tid, qname, qtype, question


def build_response(tid, question, answers, rcode=0) -> bytes:
    """answers: list of (rtype, rdata_bytes). The answer name is a pointer
    (0xC00C) back to the echoed question's QNAME at offset 12."""
    flags = 0x8180 | (rcode & 0xF)  # QR=1, RD=1, RA=1, rcode
    header = tid + struct.pack(">HHHHH", flags, 1, len(answers), 0, 0)
    pkt = header + question
    for rtype, rdata in answers:
        pkt += b"\xc0\x0c"
        pkt += struct.pack(">HHI", rtype, 1, 60)  # type, class IN, TTL (32-bit)
        pkt += struct.pack(">H", len(rdata)) + rdata
    return pkt


def load_wildcard_bases(pinfile):
    """Wildcard bases from <dir>/wildcards.txt (next to the pin file), one
    `*.domain` per line; unparseable lines drop."""
    base_dir = os.path.dirname(os.path.abspath(pinfile))
    try:
        with open(os.path.join(base_dir, "wildcards.txt")) as f:
            return [
                line.strip()[2:].lower()
                for line in f
                if line.strip().startswith("*.")
                and re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", line.strip()[2:])
            ]
    except OSError:
        return []


def matches_wildcard(name, bases):
    """Strict subdomain of a base (the base itself is not a match)."""
    return any(name.endswith("." + b) and name.count(".") > b.count(".") for b in bases)


def load_denied(pinfile):
    """deniedDomains from <dir>/denied.txt (next to the pin file): `*` denies
    every name, `*.domain` strict subdomains, anything else an exact name.
    Returns (deny_all, names, suffixes)."""
    base_dir = os.path.dirname(os.path.abspath(pinfile))
    deny_all, names, suffixes = False, set(), []
    try:
        with open(os.path.join(base_dir, "denied.txt")) as f:
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
    deny_all, names, suffixes = denied
    return deny_all or name in names or any(name.endswith(s) for s in suffixes)


def query_agent(sock_path, name, qtype):
    """One vouch request to the in-netns agent. (2, []) when it is not there."""
    try:
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(7.0)
        conn.connect(sock_path)
        conn.sendall(f"{name} {qtype}\n".encode())
        line = conn.makefile("rb").readline()
        conn.close()
        parts = line.decode().strip().split("\t")
        if not parts:
            # Agent closed without answering (should not happen): fail closed.
            return 2, []
        return int(parts[0]), (parts[1].split() if len(parts) > 1 else [])
    except (OSError, ValueError):
        return 2, []


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    port = int(sys.argv[1])
    pinfile = sys.argv[2]
    addr = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"
    base_dir = os.path.dirname(os.path.abspath(pinfile))
    agent_sock = os.path.join(base_dir, "agent.sock")

    pins = {}
    with open(pinfile) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            pins.setdefault(parts[0].lower(), []).extend(parts[1:])

    bases = load_wildcard_bases(pinfile)
    denied = load_denied(pinfile)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, port))
    sys.stderr.write(
        f"responder listening on {addr}:{port}, {len(pins)} pinned name(s), "
        f"{len(bases)} wildcard base(s)\n"
    )
    sys.stderr.flush()

    while True:
        try:
            pkt, client = s.recvfrom(1500)
        except OSError:
            break
        try:
            tid, qname, qtype, question = parse_question(pkt)
        except Exception:
            continue
        answers = []
        rcode = 0
        ips = pins.get(qname)
        if not ips:
            # Not pinned. A strict subdomain of an allowlisted wildcard base
            # is vouched on demand through the agent (upstream resolver +
            # egress rule); everything else is NXDOMAIN. (A 0.0.0.0 sinkhole
            # would point at the local host, and "unknown host" is the
            # clearer failure.) Denials take precedence over wildcards; the
            # upstream resolver enforces them again.
            if (
                agent_sock
                and bases
                and matches_wildcard(qname, bases)
                and not is_denied(qname, denied)
            ):
                rcode, ips = query_agent(agent_sock, qname, qtype)
            else:
                rcode = 3
        if rcode == 0 and ips:
            if qtype == 1:  # A
                answers = [(1, socket.inet_aton(ip)) for ip in ips if ":" not in ip]
            elif qtype == 28:  # AAAA
                answers = [
                    (28, socket.inet_pton(socket.AF_INET6, ip)) for ip in ips if ":" in ip
                ]
            # other qtypes: empty answer (ancount=0)
        # rcode 2 (SERVFAIL) and 3 (NXDOMAIN) answer with no records
        try:
            s.sendto(build_response(tid, question, answers, rcode), client)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
