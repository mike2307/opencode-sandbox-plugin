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
  if (entry.includes("*"))
    return {
      kind: "skip",
      entry,
      reason: "wildcard domains are not supported by the v1 fence",
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
  const skips: FenceSkip[] = []
  const seenPins = new Set<string>()
  const seenNetworks = new Set<string>()
  for (const raw of entries) {
    const entry = parseFenceEntry(raw)
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
    if (seenPins.has(entry.name)) continue
    let ips: string[]
    try {
      ips = await resolve4(entry.name)
    } catch (err) {
      skips.push({
        entry: entry.name,
        reason: `resolution failed: ${err instanceof Error ? err.message : String(err)}`,
      })
      continue
    }
    const v4 = [...new Set(ips.filter((ip) => ipv4Valid(ip)))].sort()
    if (v4.length === 0) {
      skips.push({ entry: entry.name, reason: "resolved no IPv4 addresses" })
      continue
    }
    seenPins.add(entry.name)
    pins.push({ name: entry.name, ips: v4 })
  }
  return { pins, networks, skips }
}

function ipv4Valid(ip: string): boolean {
  const m = ip.match(IPV4_RE)
  return !!m && validOctets(m.slice(1, 5))
}

/** The egress-responder asset bundled with the plugin (dist/fence/ in the build). */
function responderAssetPath(): string {
  return path.join(path.dirname(fileURLToPath(import.meta.url)), "fence", "egress-responder.py")
}

export type FenceCommand = {
  /** Shell command that runs `wrapped` through the pasta fence. */
  command: string
  /** Per-command scratch dir; the guest removes it on exit, the plugin sweeps stale ones. */
  dir: string
}

export type BuildFenceOptions = {
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
  const parsed = await parseFenceAllowlist(allowlist, options.resolve4)
  for (const skip of parsed.skips)
    warn(`[opencode-sandbox] fence: ignoring allowlist entry ${skip.entry} — ${skip.reason}`)

  const dir = await fsPromises.mkdtemp(path.join(os.tmpdir(), FENCE_DIR_PREFIX))
  try {
    const responder = await fsPromises.readFile(responderAssetPath())
    // bwrap runs as guest root in the pasta namespace: the seccomp helper's
    // nested user namespace needs CAP_SETFCAP to map uid 0 (kernels >= 5.12).
    const wrappedInGuest = fenceCapabilityFix(wrapped)
    await Promise.all([
      fsPromises.writeFile(path.join(dir, "egress-responder.py"), responder),
      fsPromises.writeFile(path.join(dir, "guest.sh"), GUEST_SH),
      fsPromises.writeFile(path.join(dir, "setup.sh"), NAMESPACE_SETUP_SH),
      fsPromises.writeFile(path.join(dir, "runner.sh"), MOUNT_RUNNER_SH),
      fsPromises.writeFile(path.join(dir, "resolv.conf"), RESOLV_CONF),
      fsPromises.writeFile(path.join(dir, "nsswitch.conf"), NSSWITCH_CONF),
      fsPromises.writeFile(path.join(dir, "pin.txt"), pinLines(parsed.pins)),
      fsPromises.writeFile(path.join(dir, "nft.rules"), nftRules(parsed)),
      // The wrapped command is already a fully quoted command line
      // (the runtime quotes every word); as the body of a sh script it is
      // parsed into exactly the argv bwrap expects.
      fsPromises.writeFile(path.join(dir, "wrapped.sh"), `#!/bin/sh\nexec ${wrappedInGuest}\n`),
    ])
  } catch (err) {
    await fsPromises.rm(dir, { recursive: true, force: true }).catch(() => {})
    throw err
  }
  return {
    command: fenceCommand(dir),
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

/** The exact pasta invocation for a scratch dir (exported for tests). */
export function fenceCommand(dir: string, username: string = os.userInfo().username): string {
  // Entry command is an ABSOLUTE /usr/bin/bash on purpose: a bare name would
  // make pasta execvp() it, whose PATH search hits ~/.local/bin — a `search`
  // the pasta_t SELinux domain is denied.
  //
  // pasta's own stderr (its IPv6 info lines on hosts without usable IPv6,
  // and any real setup error) would otherwise leak into the command's stderr
  // verbatim. Route it through a per-command file named after the fence dir
  // (sweepFenceDirs reaps it if this command is killed before the rm below),
  // filter the known chatter, replay the rest, restore pasta's exit status.
  const tag = path.basename(dir).slice(FENCE_DIR_PREFIX.length)
  const errFile = path.join(path.dirname(dir), `${FENCE_DIR_PREFIX}pasta-${tag}.err`)
  const noise = PASTA_NOISE_LINES.map((line) => `-e ${shQuote(line)}`).join(" ")
  return [
    `pasta --config-net --runas ${shQuote(username)} /usr/bin/bash ${shQuote(path.join(dir, "guest.sh"))} 2>${shQuote(errFile)}`,
    "_rc=$?",
    `grep -v ${noise} <${shQuote(errFile)} >&2 2>/dev/null`,
    `rm -f ${shQuote(errFile)}`,
    "exit $_rc",
  ].join("\n")
}

/** pasta's harmless setup chatter, filtered out of the command's stderr. */
const PASTA_NOISE_LINES = [
  "No interfaces with usable IPv6 routes",
  "IPv6: no external interface as template, use local mode",
]

function pinLines(pins: FencePin[]): string {
  if (pins.length === 0) return ""
  return `${pins.map((pin) => `${pin.name} ${pin.ips.join(" ")}`).join("\n")}\n`
}

function nftRules(parsed: FenceParsed): string {
  const lines = [
    "flush ruleset",
    "add table ip egress",
    "add chain ip egress output { type filter hook output priority 0; policy drop; }",
    "add rule ip egress output oifname lo accept",
    `add rule ip egress output ip daddr ${DNS_ADDR} udp dport 53 accept`,
    "add rule ip egress output ct state established,related accept",
  ]
  for (const pin of parsed.pins)
    for (const ip of pin.ips) lines.push(`add rule ip egress output ip daddr ${ip} accept`)
  for (const network of parsed.networks)
    lines.push(`add rule ip egress output ip daddr ${network} accept`)
  return `${lines.join("\n")}\n`
}

const shQuote = (value: string) => `'${value.replace(/'/g, `'\\''`)}'`

/**
 * Fence scratch dirs (and the per-command pasta-stderr files, named
 * opencode-fence-* as well) left behind by a killed command (the guest
 * removes its own dir on every exit path it reaches; the stderr file is
 * removed by the fence command itself). Remove opencode-fence-* entries
 * under tmpdir whose mtime is older than maxAgeMs. Returns how many were
 * removed.
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

/** Tools the fence needs on the host, in the order the guest uses them. */
export const FENCE_DEPENDENCIES = ["pasta", "python3", "ip", "nft", "unshare"]

/** Names of FENCE_DEPENDENCIES missing from PATH (empty when all are present). */
export function fenceDependenciesMissing(envPath: string = process.env.PATH ?? ""): string[] {
  const dirs = envPath.split(":").filter(Boolean)
  return FENCE_DEPENDENCIES.filter(
    (name) => !dirs.some((dir) => executableAt(path.join(dir, name))),
  )
}

function executableAt(p: string): boolean {
  try {
    fs.accessSync(p, fs.constants.X_OK)
    return fs.statSync(p).isFile()
  } catch {
    return false
  }
}
