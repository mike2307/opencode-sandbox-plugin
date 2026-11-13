#!/usr/bin/env python3
"""
egress-responder.py — minimal in-netns DNS pinning responder (opencode-sandbox
fence asset).

A deliberately tiny UDP DNS server that answers ONLY what a pin file says, and
sinkholes everything else. No privilege drop, no upstream, no daemon.

  usage:  egress-responder.py <port> <pinfile> [addr]
    pinfile: one allowed name per line ->
                <name> <ip> [<ip> ...]
          (a name absent from the pin file is sinkholed with NXDOMAIN). This is
           the NAME gate of the egress model.

Only A (1) and AAAA (28) queries of pinned names are answered; other qtypes of
pinned names get an empty NOERROR answer. Single-question queries only (which
is what resolvers send).
"""
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


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    port = int(sys.argv[1])
    pinfile = sys.argv[2]
    addr = sys.argv[3] if len(sys.argv) > 3 else "127.0.0.1"

    pins = {}
    with open(pinfile) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            pins.setdefault(parts[0].lower(), []).extend(parts[1:])

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, port))
    sys.stderr.write(f"responder listening on {addr}:{port}, {len(pins)} pinned name(s)\n")
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
            # Not allowlisted: NXDOMAIN. (A 0.0.0.0 sinkhole would point at
            # the local host, and "unknown host" is the clearer failure.)
            rcode = 3
        elif qtype == 1:  # A
            answers = [(1, socket.inet_aton(ip)) for ip in ips if ":" not in ip]
        elif qtype == 28:  # AAAA
            answers = [(28, socket.inet_pton(socket.AF_INET6, ip)) for ip in ips if ":" in ip]
        # other qtypes: empty answer (ancount=0)
        try:
            s.sendto(build_response(tid, question, answers, rcode), client)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
