// Static scripts of the pasta egress fence. Each per-command fence run writes
// these verbatim into its scratch dir and execs them there (guest.sh is pasta's
// entry command, so the single-quote `bash -c` invariant does not apply).
//
// Model (proxy-less, unprivileged, no host CAPs):
//
//   pasta --config-net -4         owns the network namespace (guest is uid 0 in
//   (no port forwarding,          the pasta user namespace => local
//    no gateway->host mapping)    CAP_NET_ADMIN, free :53 bind, veth, nft).
//   + /usr/bin/bash guest.sh      pasta runs it as PID 1 of a fresh PID
//                                 namespace: when it exits or is killed, the
//                                 kernel kills the responder with it.
//     + setup.sh  (unshare --net) pinning DNS responder in its OWN netns at
//                                 10.9.9.2, reached over a veth from the guest
//                                 (pasta bridges a wildcard 0.0.0.0:53 into the
//                                 guest netns that blocks every :53 bind).
//     + nft.rules (in the guest    egress allowlist: loopback + the dns endpoint
//             netns)               + the allowed destination IPs/CIDRs; policy
//                                  drop. The IP backstop: hardcoded IPs, DoH, or
//                                  a rebind that slips past DNS still hits it.
//     + runner.sh (unshare --mount) isolated mount ns: bind-override
//                                 /etc/resolv.conf (nameserver 10.9.9.2) and
//                                 /etc/nsswitch.conf (hosts: files dns — the
//                                 default line short-circuits at mdns4_minimal
//                                 before the dns module ever reads
//                                 resolv.conf) over the host targets; host
//                                 /etc untouched. Then execs wrapped.sh.
//     + wrapped.sh                  the runtime's bwrap (filesystem-sandbox)
//                                   command, which does NOT unshare net, so the
//                                   user command inherits the guest netns and
//                                   egresses only through the fence.
//
// The bind mounts survive bwrap: it starts from the parent mount table (its
// `--ro-bind / /` carries the submounts with it).
//
// INVARIANTS for these template literals: they must contain no backticks, no
// ${ (bash brace-expansion would be swallowed by the JS template), and no \
// escape sequences (the scripts are byte-exact; a stray \n would turn into a
// real newline and break a bash string).

/** Fence guest: pasta's entry command, inside the guest (pasta) netns. */
export const GUEST_SH = `#!/bin/bash
# opencode-sandbox egress fence — guest entry (runs inside the pasta netns).
# Everything the fence needs lives next to this script (DIR).
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"

RESP_PID=""
fail() {
  echo "opencode-sandbox fence: $1" >&2
  kill "$RESP_PID" 2>/dev/null
  ip link del dns0 2>/dev/null
  rm -rf "$DIR"
  exit 1
}

# 1. veth pair in this netns: dns0 stays here, dns1 moves to the responder
#    netns below. /30: 10.9.9.1 (guest) <-> 10.9.9.2 (responder).
ip link add dns0 type veth peer name dns1 || fail "creating the dns veth pair"
ip addr add 10.9.9.1/30 dev dns0 || fail "addressing the dns veth pair"
ip link set dns0 up || fail "bringing up the dns veth pair"

# 2. pinning responder in its OWN fresh netns (clean :53), in the background.
unshare --net /usr/bin/bash "$DIR/setup.sh" "$DIR/egress-responder.py" "$DIR/pin.txt" >"$DIR/resp.log" 2>&1 &
RESP_PID=$!
# Move the veth peer into the responder netns. Wait until the child has
# actually entered its new netns first: before that, its /proc ns link still
# equals ours and "moving" dns1 there is a silent no-op that strands it here.
SELF_NS="$(readlink /proc/self/ns/net)"
MOVED=""
for i in $(seq 1 250); do
  CHILD_NS="$(readlink "/proc/$RESP_PID/ns/net" 2>/dev/null)"
  if [ -n "$CHILD_NS" ] && [ "$CHILD_NS" != "$SELF_NS" ] &&
    ip link set dns1 netns "$RESP_PID" 2>/dev/null; then
    MOVED=1
    break
  fi
  kill -0 "$RESP_PID" 2>/dev/null || break
  sleep 0.02
done
[ -n "$MOVED" ] || fail "moving the dns veth peer into the responder netns"
# Wait for the responder's readiness line instead of a fixed delay.
READY=""
for i in $(seq 1 250); do
  if grep -q "^responder listening" "$DIR/resp.log" 2>/dev/null; then
    READY=1
    break
  fi
  kill -0 "$RESP_PID" 2>/dev/null || break
  sleep 0.02
done
if [ -z "$READY" ]; then
  echo "opencode-sandbox fence: the dns responder did not come up:" >&2
  cat "$DIR/resp.log" >&2
  fail "dns responder failed"
fi

# 3. egress allowlist in this netns: loopback, the dns endpoint, the allowed
#    destinations, established flows; drop everything else.
nft -f "$DIR/nft.rules" || fail "loading the egress firewall"

# 4. the wrapped (filesystem-sandboxed) command, in an isolated mount
#    namespace with the resolver + nsswitch overrides.
unshare --mount /usr/bin/bash "$DIR/runner.sh"
rc=$?

# 5. best-effort cleanup; the plugin also sweeps stale dirs at startup.
kill "$RESP_PID" 2>/dev/null
ip link del dns0 2>/dev/null
rm -rf "$DIR"
exit "$rc"
`

/** Fence setup: runs in the responder's own fresh netns (unshare --net). */
export const NAMESPACE_SETUP_SH = `#!/bin/bash
# opencode-sandbox egress fence — responder-netns setup.
# Args: $1 = egress-responder.py path, $2 = pin file.
set -u
RESPONDER="$1"
PIN="$2"
DNS_IP=10.9.9.2
IF=dns1
# Wait for the veth peer to be moved into this netns.
for i in $(seq 1 250); do
  ip -o link show "$IF" >/dev/null 2>&1 && break
  sleep 0.02
done
if ! ip -o link show "$IF" >/dev/null 2>&1; then
  echo "fence: $IF never appeared in this netns" >&2
  exit 1
fi
ip link set "$IF" up
ip addr add "$DNS_IP"/30 dev "$IF"
# Bind the pinning responder to the veth address on the clean :53.
exec /usr/bin/python3 "$RESPONDER" 53 "$PIN" "$DNS_IP"
`

/** Fence runner: runs in an isolated mount namespace (unshare --mount). */
export const MOUNT_RUNNER_SH = `#!/bin/bash
# opencode-sandbox egress fence — mount-ns overrides, then the wrapped command.
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
# /etc/resolv.conf may be a symlink (systemd-resolved); bind over its REAL
# target so the symlink still reads our content.
RT="$(readlink -f /etc/resolv.conf)"
mount --bind "$DIR/resolv.conf" "$RT" || exit 1
# Without this, NSS short-circuits name lookup (mdns4_minimal [NOTFOUND=return])
# before the dns module ever reads resolv.conf.
NT="$(readlink -f /etc/nsswitch.conf)"
mount --bind "$DIR/nsswitch.conf" "$NT" || exit 1
exec /bin/sh "$DIR/wrapped.sh"
`

/** Guest resolver: the pinning responder, reached over the veth. */
export const RESOLV_CONF = `nameserver 10.9.9.2
`

/** Guest NSS: minimal, plain files + dns (no myhostname/mDNS/SSSD magic). */
export const NSSWITCH_CONF = `passwd: files
group: files
shadow: files
hosts: files dns
networks: files
services: files
protocols: files
ethers: files
rpc: files
`
