import { spawn } from "node:child_process"
import dns from "node:dns/promises"
import fs from "node:fs"
import fsPromises from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import {
  GUEST_SH,
  MOUNT_RUNNER_SH,
  NAMESPACE_SETUP_SH,
  NSSWITCH_CONF,
  RESOLV_CONF,
} from "./fence-assets"

// pasta egress fence (Linux only): the plugin owns the network per command —
// src/fence-assets.ts documents the model (a pasta netns around the
// runtime's pure-filesystem bwrap). The runtime itself runs with networking
// disabled (no --unshare-net, no proxy), so the bwrap filesystem sandbox
// nests inside the pasta netns untouched.
//
// v1 allowlist semantics (fail-closed):
//   - exact domains  -> resolved on the host at setup, pinned into the
//                       in-netns responder (name gate) and the nft backstop
//   - IPv4 literals and CIDRs -> nft destination rules (all ports)
//   - wildcards, port-suffixed entries, IPv6 -> skipped with a warning

/** Scratch-dir prefix under os.tmpdir(); per-command dirs are opencode-fence-XXXX. */
export const FENCE_DIR_PREFIX = "opencode-fence-"
/** veth wiring: guest 10.9.9.1 <-> responder 10.9.9.2 (/30). */
const DNS_ADDR = "10.9.9.2"

export type FencePin = { name: string; ips: string[] }
export type FenceSkip = { entry: string; reason: string }
export type FenceParsed = {
  /** exact domains resolved to their pinned IPv4 addresses (name gate). */
  pins: FencePin[]
  /** `*.domain` wildcard bases: strict subdomains are resolved on demand. */
  wildcards: string[]
  /** IPv4 literals and CIDRs, ready for nft (IP backstop). */
  networks: string[]
  /** entries the v1 fence cannot express, with the reason. */
  skips: FenceSkip[]
}

/** A resolver standing in for dns.resolve4 in tests. */
export type Resolve4 = (name: string) => Promise<string[]>

export type FenceEntry =
  | { kind: "domain"; name: string }
  | { kind: "network"; value: string }
  | { kind: "wildcard"; base: string }
  | { kind: "skip"; entry: string; reason: string }

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
const IPV4_CIDR_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/
// RFC 952-ish hostname labels: alphanumeric, hyphens not at either end.
const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i

const validOctets = (octets: string[]) => octets.every((o) => Number(o) <= 255)

/** Classify one allowlist entry (no I/O; resolution happens in parseFenceAllowlist). */
export function parseFenceEntry(raw: string): FenceEntry {
  const entry = raw.trim()
  if (!entry) return { kind: "skip", entry, reason: "empty entry" }
  if (entry.includes("*")) {
    // `*.domain` is the only wildcard form: subdomains are resolved on
    // demand. Over-broad bases (a single label, as in `*.com`) are refused
    // exactly like the runtime schema refuses them.
    const base = entry.match(/^\*\.(.+)$/)?.[1]
    if (base?.includes(".") && DOMAIN_RE.test(base))
      return { kind: "wildcard", base: base.toLowerCase() }
    return {
      kind: "skip",
      entry,
      reason: base
        ? "overly broad wildcard (the base needs at least two labels)"
        : "wildcard domains must be of the form *.domain",
    }
  }
  // A colon means either a port suffix (name:port / ip:port) or IPv6; neither
  // is expressible in v1 (the fence pins whole destinations, without per-port
  // or IPv6 rules).
  if (entry.includes(":")) {
    const [head, ...rest] = entry.split(":")
    const isPortSuffix = rest.length === 1 && /^\d+$/.test(rest[0]) && !head.includes(":")
    return {
      kind: "skip",
      entry,
      reason: isPortSuffix
        ? "port-suffixed entries are not supported by the v1 fence"
        : "IPv6 is not supported by the v1 fence",
    }
  }
  const cidr = entry.match(IPV4_CIDR_RE)
  if (cidr) {
    if (!validOctets(cidr.slice(1, 5)))
      return { kind: "skip", entry, reason: "invalid IPv4 address" }
    if (Number(cidr[5]) > 32) return { kind: "skip", entry, reason: "invalid prefix length" }
    return { kind: "network", value: entry }
  }
  const ip = entry.match(IPV4_RE)
  if (ip) {
    if (!validOctets(ip.slice(1, 5))) return { kind: "skip", entry, reason: "invalid IPv4 address" }
    return { kind: "network", value: entry }
  }
  if (!DOMAIN_RE.test(entry)) return { kind: "skip", entry, reason: "not a valid hostname" }
  return { kind: "domain", name: entry.toLowerCase() }
}

/**
 * Split an allowlist into pinned domains, nft networks, and skips.
 * Domains are resolved with `resolve4` (host-side, per command run); a domain
 * that resolves to nothing is skipped, not pinned (fail-closed).
 */
export async function parseFenceAllowlist(
  entries: string[],
  resolve4: Resolve4 = (name) => dns.resolve4(name),
): Promise<FenceParsed> {
  const pins: FencePin[] = []
  const networks: string[] = []
  const wildcards: string[] = []
  const skips: FenceSkip[] = []
  const seenNetworks = new Set<string>()
  const parsedEntries = entries.map(parseFenceEntry)
  // Resolve every distinct domain concurrently: one slow name must not add
  // its latency to every other lookup.
  const domains = [...new Set(parsedEntries.flatMap((e) => (e.kind === "domain" ? [e.name] : [])))]
  const resolved = new Map(
    await Promise.all(
      domains.map(
        async (name) =>
          [
            name,
            await resolve4(name).then(
              (ips) => ({ ips }),
              (err: unknown) => ({ error: err instanceof Error ? err.message : String(err) }),
            ),
          ] as const,
      ),
    ),
  )
  const seenPins = new Set<string>()
  const seenWildcards = new Set<string>()
  for (const entry of parsedEntries) {
    if (entry.kind === "skip") {
      skips.push({ entry: entry.entry, reason: entry.reason })
      continue
    }
    if (entry.kind === "network") {
      if (!seenNetworks.has(entry.value)) {
        seenNetworks.add(entry.value)
        networks.push(entry.value)
      }
      continue
    }
    if (entry.kind === "wildcard") {
      if (!seenWildcards.has(entry.base)) {
        seenWildcards.add(entry.base)
        wildcards.push(entry.base)
      }
      continue
    }
    if (seenPins.has(entry.name)) continue
    seenPins.add(entry.name)
    const result = resolved.get(entry.name)
    if (!result || "error" in result) {
      skips.push({ entry: entry.name, reason: `resolution failed: ${result?.error}` })
      continue
    }
    const v4 = [...new Set(result.ips.filter((ip) => ipv4Valid(ip)))].sort()
    if (v4.length === 0) {
      skips.push({ entry: entry.name, reason: "resolved no IPv4 addresses" })
      continue
    }
    pins.push({ name: entry.name, ips: v4 })
  }
  return { pins, wildcards, networks, skips }
}

export type FenceDenied = {
  /** exact domains, lowercased: never pinned. */
  names: Set<string>
  /** `*.domain` suffixes (".domain"): no subdomain of these is pinned. */
  suffixes: string[]
  /** `*`: no domain allowlist entry is pinned (raw IP/CIDR entries are kept,
   * as the proxy model denies names, not raw IPs). */
  allNames: boolean
  /** IPv4 literals and CIDRs: dropped ahead of every accept rule. */
  networks: string[]
  /** entries the v1 fence cannot express. */
  skips: FenceSkip[]
}

/**
 * Classify deniedDomains for the fence. Denials only ever narrow the
 * allowlist: a denied name is never pinned (so it gets NXDOMAIN), a denied
 * IPv4/CIDR is dropped by nft even inside an allowed CIDR, and `*` (deny-all)
 * leaves no domain entry pinned while raw IP/CIDR entries stay effective —
 * the same as the proxy model, where `*` matches names, not IP destinations.
 */
export function parseFenceDenylist(entries: string[]): FenceDenied {
  const denied: FenceDenied = {
    names: new Set(),
    suffixes: [],
    allNames: false,
    networks: [],
    skips: [],
  }
  for (const raw of entries) {
    const entry = raw.trim()
    if (entry === "*") {
      denied.allNames = true
      continue
    }
    const wildcard = entry.match(/^\*\.(.+)$/)
    if (wildcard && DOMAIN_RE.test(wildcard[1])) {
      denied.suffixes.push(`.${wildcard[1].toLowerCase()}`)
      continue
    }
    const parsed = parseFenceEntry(entry)
    if (parsed.kind === "domain") denied.names.add(parsed.name)
    else if (parsed.kind === "network") denied.networks.push(parsed.value)
    else if (parsed.kind === "wildcard")
      // Unreachable in practice (valid wildcards were matched above), but the
      // deny semantics of one are a suffix denial.
      denied.suffixes.push(`.${parsed.base}`)
    else denied.skips.push({ entry: parsed.entry, reason: parsed.reason })
  }
  return denied
}

/** Whether an allowlist entry names a denied domain (exact or by wildcard). */
function isDeniedName(entry: string, denied: FenceDenied): boolean {
  const name = entry.trim().toLowerCase()
  return denied.names.has(name) || denied.suffixes.some((suffix) => name.endsWith(suffix))
}

function ipv4Valid(ip: string): boolean {
  const m = ip.match(IPV4_RE)
  return !!m && validOctets(m.slice(1, 5))
}

/** The fence python assets bundled with the plugin (dist/fence/ in the build). */
function fenceAssetPath(name: string): string {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), "fence", name)
}

export type FenceCommand = {
  /** Shell command that runs `wrapped` through the pasta fence. */
  command: string
  /** Per-command scratch dir; the guest removes it on exit, the plugin sweeps stale ones. */
  dir: string
}

export type BuildFenceOptions = {
  /** deniedDomains: removed from the allowlist (names) or dropped ahead of it (IPv4/CIDR). */
  denylist?: string[]
  /** Resolver standing in for dns.resolve4 (tests). */
  resolve4?: Resolve4
  /** Sink for skip warnings (defaults to console.warn). */
  warn?: (message: string) => void
}

/**
 * Build the per-command fence: a scratch dir with the static scripts, the
 * pinned names, the nft ruleset, and the wrapped (bwrap) command — plus the
 * `pasta` invocation that runs it. The guest removes the dir when done.
 */
export async function buildFenceCommand(
  wrapped: string,
  allowlist: string[],
  options: BuildFenceOptions = {},
): Promise<FenceCommand> {
  const warn = options.warn ?? ((message: string) => console.warn(message))
  const denied = parseFenceDenylist(options.denylist ?? [])
  for (const skip of denied.skips)
    warn(`[opencode-sandbox] fence: ignoring denylist entry ${skip.entry} — ${skip.reason}`)
  const parsed = await parseFenceAllowlist(
    allowlist.filter((entry) => {
      // `*` denies every NAME: exact domains and wildcards alike; raw
      // IP/CIDR entries stay (the proxy model matches names, not IPs).
      const kind = parseFenceEntry(entry).kind
      if (denied.allNames && (kind === "domain" || kind === "wildcard")) return false
      return !isDeniedName(entry, denied)
    }),
    options.resolve4,
  )
  for (const skip of parsed.skips)
    warn(`[opencode-sandbox] fence: ignoring allowlist entry ${skip.entry} — ${skip.reason}`)

  const dir = await fsPromises.mkdtemp(path.join(os.tmpdir(), FENCE_DIR_PREFIX))
  try {
    const responder = await fsPromises.readFile(fenceAssetPath("egress-responder.py"))
    const upstream = await fsPromises.readFile(fenceAssetPath("upstream-resolver.py"))
    const agent = await fsPromises.readFile(fenceAssetPath("fence-agent.py"))
    // bwrap runs as guest root in the pasta namespace: the seccomp helper's
    // nested user namespace needs CAP_SETFCAP to map uid 0 (kernels >= 5.12).
    const wrappedInGuest = fenceCapabilityFix(wrapped)
    await Promise.all([
      fsPromises.writeFile(path.join(dir, "egress-responder.py"), responder),
      fsPromises.writeFile(path.join(dir, "upstream-resolver.py"), upstream),
      fsPromises.writeFile(path.join(dir, "fence-agent.py"), agent),
      fsPromises.writeFile(path.join(dir, "guest.sh"), GUEST_SH),
      fsPromises.writeFile(path.join(dir, "setup.sh"), NAMESPACE_SETUP_SH),
      fsPromises.writeFile(path.join(dir, "runner.sh"), MOUNT_RUNNER_SH),
      fsPromises.writeFile(path.join(dir, "resolv.conf"), RESOLV_CONF),
      fsPromises.writeFile(path.join(dir, "nsswitch.conf"), NSSWITCH_CONF),
      fsPromises.writeFile(path.join(dir, "pin.txt"), pinLines(parsed.pins)),
      fsPromises.writeFile(path.join(dir, "wildcards.txt"), wildcardLines(parsed.wildcards)),
      // Wildcard lookups happen at runtime, so the denials must travel with
      // them: the responder and the upstream resolver both refuse these.
      fsPromises.writeFile(path.join(dir, "denied.txt"), deniedLines(denied)),
      fsPromises.writeFile(path.join(dir, "nft.rules"), nftRules(parsed, denied.networks)),
      // The wrapped command is already a fully quoted command line
      // (the runtime quotes every word with POSIX single quotes); as the body
      // of a sh script it is parsed into exactly the argv bwrap expects.
      fsPromises.writeFile(path.join(dir, "wrapped.sh"), `#!/bin/sh\nexec ${wrappedInGuest}\n`),
    ])
  } catch (err) {
    await fsPromises.rm(dir, { recursive: true, force: true }).catch(() => {})
    throw err
  }
  return {
    command: fenceCommand(dir, os.userInfo().username, parsed.wildcards.length > 0),
    dir,
  }
}

/**
 * The bwrap command runs as GUEST ROOT inside the pasta namespace. Its
 * `--unshare-user --cap-drop ALL` leaves the seccomp helper (apply-seccomp,
 * which the runtime prefixes on Linux) without any capability, and kernels
 * since 5.12 allow a uid-0 mapping in a nested user namespace only from a
 * creator holding CAP_SETFCAP in the parent namespace — so the helper dies
 * with `write /proc/self/uid_map: Operation not permitted`. The runtime adds
 * `--cap-add CAP_SETFCAP` for this exact condition itself, but keyed on its
 * own process euid being 0, which never holds here (the host user drives
 * the fence); apply the same fix to the wrapped command instead. The flag
 * is a bwrap option, and the runtime emits it exactly once, before the user
 * command, in every rendered form (inline or `--args` file).
 *
 * The "already present" test is adjacency to the FIRST `--cap-drop ALL`, not
 * a whole-string scan: the user command follows on the same line, and its
 * text may contain the same words (a commit message documenting this very
 * fix tripped the naive scan once — the cap was then missing from the real
 * bwrap line, and apply-seccomp died on the uid_map write).
 */
export function fenceCapabilityFix(wrapped: string): string {
  const at = wrapped.indexOf("--cap-drop ALL")
  if (at === -1) return wrapped
  const after = wrapped.slice(at + "--cap-drop ALL".length)
  if (after.startsWith(" --cap-add CAP_SETFCAP")) return wrapped
  return wrapped.slice(0, at + "--cap-drop ALL".length) + " --cap-add CAP_SETFCAP" + after
}

/** The fence command for a scratch dir (exported for tests). With wildcard
 * entries the command also manages the host-side upstream resolver: it starts
 * it before pasta, fails closed if it does not come up, and kills it after. */
export function fenceCommand(
  dir: string,
  username: string = os.userInfo().username,
  withWildcardDaemon = false,
): string {
  // Entry command is an ABSOLUTE /usr/bin/bash on purpose: a bare name would
  // make pasta execvp() it, whose PATH search hits ~/.local/bin — a `search`
  // the pasta_t SELinux domain is denied.
  //
  // The guest inherits pasta's stdio, so stderr must NOT be redirected here
  // (it would swallow the command's own stderr); --quiet drops pasta's info
  // chatter instead. The wrapper lines redirect only the DAEMON's stderr
  // (its own log file), never pasta's.
  const pasta = [
    "pasta",
    ...PASTA_FENCE_OPTIONS,
    "--runas",
    shQuote(username),
    "/usr/bin/bash",
    shQuote(path.join(dir, "guest.sh")),
  ].join(" ")
  if (!withWildcardDaemon) return pasta
  const upLog = shQuote(path.join(dir, "up.log"))
  const upPid = shQuote(path.join(dir, "upstream.pid"))
  return [
    `/usr/bin/python3 ${shQuote(path.join(dir, "upstream-resolver.py"))} ${shQuote(dir)} >${upLog} 2>&1 &`,
    "UP_PID=$!",
    `echo "$UP_PID" >${upPid}`,
    // Wait for the daemon's readiness line instead of a fixed delay.
    'READY=""',
    "for i in $(seq 1 250); do",
    `  grep -q "^upstream listening" ${upLog} 2>/dev/null && { READY=1; break; }`,
    '  kill -0 "$UP_PID" 2>/dev/null || break',
    "  sleep 0.02",
    "done",
    'if [ -z "$READY" ]; then',
    '  kill "$UP_PID" 2>/dev/null',
    '  echo "opencode-sandbox fence: the upstream resolver did not come up:" >&2',
    `  cat ${upLog} >&2`,
    "  exit 1",
    "fi",
    pasta,
    "rc=$?",
    'kill "$UP_PID" 2>/dev/null',
    'exit "$rc"',
  ].join("\n")
}

/**
 * pasta options of the fence. pasta's defaults would open holes around the
 * egress allowlist:
 *   -T/-U auto   forward namespace-loopback connections to ports bound on the
 *                HOST's loopback (every local service reachable via 127.0.0.1)
 *   -t/-u auto   expose ports bound inside the namespace on the host
 *   gateway map  the gateway address reaches the host's loopback
 *   IPv6         the allowlist is IPv4-only; no v6 in the namespace at all
 *                (the ruleset drops v6 as well)
 *   DNS          pasta's own resolver plumbing is unused (the fence brings
 *                its own); without --dns none it warns on every command when
 *                the host resolver is on loopback (systemd-resolved), which
 *                --no-map-gw makes unreachable — a warning --quiet keeps
 */
export const PASTA_FENCE_OPTIONS = [
  "--quiet",
  "--config-net",
  "--ipv4-only",
  "--no-map-gw",
  "--dns",
  "none",
  "--search",
  "none",
  "-t",
  "none",
  "-u",
  "none",
  "-T",
  "none",
  "-U",
  "none",
]

function pinLines(pins: FencePin[]): string {
  if (pins.length === 0) return ""
  return `${pins.map((pin) => `${pin.name} ${pin.ips.join(" ")}`).join("\n")}\n`
}

/** One `*.domain` per line; empty when the allowlist has no wildcards. */
function wildcardLines(wildcards: string[]): string {
  if (wildcards.length === 0) return ""
  return `${wildcards.map((base) => `*.${base}`).join("\n")}\n`
}

/** Denied names for the runtime (wildcard) lookups: exact names, `*.domain`
 * suffixes, and `*` for deny-all; empty when nothing is denied by name. */
function deniedLines(denied: FenceDenied): string {
  const lines = [
    ...(denied.allNames ? ["*"] : []),
    ...denied.names,
    ...denied.suffixes.map((suffix) => `*${suffix}`),
  ]
  return lines.length === 0 ? "" : `${lines.join("\n")}\n`
}

function nftRules(parsed: FenceParsed, deniedNetworks: string[] = []): string {
  // inet: one policy-drop chain for BOTH families, so IPv6 egress is dropped
  // (only loopback passes) even if pasta ever configured v6.
  const lines = [
    "flush ruleset",
    "add table inet egress",
    "add chain inet egress output { type filter hook output priority 0; policy drop; }",
    "add rule inet egress output oifname lo accept",
    `add rule inet egress output ip daddr ${DNS_ADDR} udp dport 53 accept`,
    "add rule inet egress output ct state established,related accept",
  ]
  for (const network of deniedNetworks)
    lines.push(`add rule inet egress output ip daddr ${network} drop`)
  for (const pin of parsed.pins)
    for (const ip of pin.ips) lines.push(`add rule inet egress output ip daddr ${ip} accept`)
  for (const network of parsed.networks)
    lines.push(`add rule inet egress output ip daddr ${network} accept`)
  return `${lines.join("\n")}\n`
}

const shQuote = (value: string) => `'${value.replace(/'/g, `'\\''`)}'`

/**
 * Fence scratch dirs left behind by a killed command (the guest removes its
 * own dir on every exit path it reaches; older plugin versions also left
 * opencode-fence-pasta-*.err files). Remove opencode-fence-* entries under
 * tmpdir whose mtime is older than maxAgeMs. Returns how many were removed.
 */
export async function sweepFenceDirs(
  tmpdir: string = os.tmpdir(),
  maxAgeMs = 2 * 60 * 60 * 1000,
): Promise<number> {
  let names: string[]
  try {
    names = await fsPromises.readdir(tmpdir)
  } catch {
    return 0
  }
  const now = Date.now()
  let removed = 0
  for (const name of names) {
    if (!name.startsWith(FENCE_DIR_PREFIX)) continue
    const entry = path.join(tmpdir, name)
    try {
      const stat = await fsPromises.stat(entry)
      if (now - stat.mtimeMs <= maxAgeMs) continue
      await fsPromises.rm(entry, { recursive: true, force: true })
      removed++
    } catch {
      // raced or vanished; the next sweep re-sees it
    }
  }
  return removed
}

/**
 * Terminate a fence scratch dir's host-side upstream resolver daemon, if one
 * is still alive (the wrapper kills it on every exit path it reaches; this
 * covers a SIGKILLed command). Reads the pid the wrapper wrote, signals
 * SIGTERM, and removes the dir.
 */
export async function releaseFenceDir(dir: string): Promise<void> {
  try {
    const raw = await fsPromises.readFile(path.join(dir, "upstream.pid"), "utf8")
    const pid = Number(raw.trim())
    // Only signal the pid if it still IS this dir's resolver: after a killed
    // command the daemon may be gone and its pid reused by another process.
    if (Number.isInteger(pid) && pid > 0) {
      const cmdline = await fsPromises.readFile(`/proc/${pid}/cmdline`, "utf8")
      if (cmdline.split("\0").includes(path.join(dir, "upstream-resolver.py")))
        process.kill(pid, "SIGTERM")
    }
  } catch {
    // no daemon (no wildcards) or already gone
  }
  await fsPromises.rm(dir, { recursive: true, force: true })
}

/** Tools the fence needs from PATH, in the order the guest uses them. */
export const FENCE_DEPENDENCIES = ["pasta", "ip", "unshare", "nft", "mount", "readlink"]

/** Interpreters the fence scripts invoke by absolute path (not via PATH). */
export const FENCE_ABSOLUTE_DEPENDENCIES = ["/usr/bin/bash", "/usr/bin/python3", "/bin/sh"]

/**
 * Fence dependencies that are missing (empty when all are present): PATH
 * tools by name, the absolute interpreters by path.
 */
export function fenceDependenciesMissing(
  envPath: string = process.env.PATH ?? "",
  absolute: string[] = FENCE_ABSOLUTE_DEPENDENCIES,
): string[] {
  const dirs = envPath.split(":").filter(Boolean)
  return [
    ...FENCE_DEPENDENCIES.filter((name) => !dirs.some((dir) => executableAt(path.join(dir, name)))),
    ...absolute.filter((p) => !executableAt(p)),
  ]
}

/**
 * Whether this process runs with no_new_privs. pasta is normally entered
 * into its own SELinux domain (pasta_t); under no_new_privs that transition
 * is denied (AVC `nnp_transition nosuid_transition`), and pasta runs
 * unconfined in the caller's domain instead — functional, but it raises an
 * SELinux alert per command. Typical cause: opencode itself started from
 * within a sandbox (bwrap / seccomp helper / systemd NoNewPrivileges=).
 */
export function runsWithNoNewPrivs(statusFile = "/proc/self/status"): boolean {
  try {
    return /^NoNewPrivs:\s*1\s*$/m.test(fs.readFileSync(statusFile, "utf8"))
  } catch {
    return false
  }
}

/**
 * SIGKILL the process rooted at rootPid plus all its descendants (best effort:
 * a process may exit between the scan and the kill). Used when the fence
 * probe times out: killing the probe's pasta alone would orphan the guest it
 * runs in a fresh PID namespace — host-pidns descendants either way — which
 * would keep the (empty-allowlist) fence machinery alive past the probe. On
 * non-Linux (no /proc) this degenerates to killing only the root.
 */
export function killProcessTree(rootPid: number): void {
  const children = new Map<number, number[]>()
  try {
    for (const name of fs.readdirSync("/proc")) {
      if (!/^\d+$/.test(name)) continue
      const pid = Number(name)
      if (pid === rootPid) continue
      try {
        // comm is parenthesized and may contain spaces or parens, so cut
        // after the LAST ")"; PPid is the second field of what follows.
        const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8")
        const ppid = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1])
        if (!Number.isInteger(ppid)) continue
        const siblings = children.get(ppid) ?? []
        siblings.push(pid)
        children.set(ppid, siblings)
      } catch {
        // the process exited mid-scan
      }
    }
  } catch {
    // not Linux; the plain kill below is all that is possible
  }
  const doomed: number[] = []
  const stack = [rootPid]
  while (stack.length > 0) {
    const pid = stack.pop() as number
    doomed.push(pid)
    for (const child of children.get(pid) ?? []) stack.push(child)
  }
  for (const pid of doomed.reverse()) {
    try {
      process.kill(pid, "SIGKILL")
    } catch {
      // already gone
    }
  }
}

// Probe workload, run INSIDE the fence with an empty allowlist: egress to a
// public address must fail (101 otherwise) and a lookup must be refused by
// the name gate (102 otherwise). The probed name is under .invalid (RFC
// 2606, never delegated), so it cannot sit in a host /etc/hosts entry —
// `hosts: files` consults the host's file, which the fence does not override.
const FENCE_PROBE_PY = [
  "import socket, sys",
  "s = socket.socket()",
  "s.settimeout(1.5)",
  "try:",
  '    s.connect(("1.1.1.1", 443))',
  "    sys.exit(101)",
  "except OSError:",
  "    pass",
  "try:",
  '    socket.getaddrinfo("opencode-sandbox-probe.invalid", 443)',
  "    sys.exit(102)",
  "except OSError:",
  "    pass",
].join("\n")

const FENCE_PROBE_TIMEOUT_MS = 20_000

/**
 * Verify the fence end to end before trusting it with agent commands: pasta
 * starts, the responder comes up, the ruleset loads, and with an empty
 * allowlist both a direct connection and a name lookup fail. Throws on any
 * failure — callers fail closed.
 */
export async function runFenceProbe(options: BuildFenceOptions = {}): Promise<void> {
  const fence = await buildFenceCommand(
    `/usr/bin/python3 -c ${shQuote(FENCE_PROBE_PY)}`,
    [],
    options,
  )
  try {
    const { code, stderr } = await new Promise<{ code: number | null; stderr: string }>(
      (resolve, reject) => {
        const child = spawn("/bin/sh", ["-c", fence.command], {
          stdio: ["ignore", "ignore", "pipe"],
        })
        let stderr = ""
        child.stderr?.on("data", (chunk) => {
          if (stderr.length < 2000) stderr += String(chunk)
        })
        const timer = setTimeout(() => {
          // SIGKILLing the child (pasta) alone would orphan the guest it
          // spawned in a fresh PID namespace; kill the whole tree instead.
          if (child.pid !== undefined) killProcessTree(child.pid)
          else child.kill("SIGKILL")
          reject(new Error(`fence probe timed out after ${FENCE_PROBE_TIMEOUT_MS}ms`))
        }, FENCE_PROBE_TIMEOUT_MS)
        child.on("error", (err) => {
          clearTimeout(timer)
          reject(err)
        })
        child.on("close", (code) => {
          clearTimeout(timer)
          resolve({ code, stderr })
        })
      },
    )
    if (code === 0) return
    if (code === 101) throw new Error("fence probe: a non-allowlisted address was reachable")
    if (code === 102) throw new Error("fence probe: a non-allowlisted name resolved")
    throw new Error(`fence probe failed (exit ${code}): ${stderr.trim() || "no output"}`)
  } finally {
    await fsPromises.rm(fence.dir, { recursive: true, force: true }).catch(() => {})
  }
}

function executableAt(p: string): boolean {
  try {
    fs.accessSync(p, fs.constants.X_OK)
    return fs.statSync(p).isFile()
  } catch {
    return false
  }
}
