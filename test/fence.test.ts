import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import fs from "node:fs"
import fsPromises from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import {
  buildFenceCommand,
  FENCE_DEPENDENCIES,
  FENCE_DIR_PREFIX,
  fenceCapabilityFix,
  fenceCommand,
  fenceDependenciesMissing,
  PASTA_FENCE_OPTIONS,
  parseFenceAllowlist,
  parseFenceDenylist,
  parseFenceEntry,
  type Resolve4,
  runsWithNoNewPrivs,
  sweepFenceDirs,
} from "../src/fence"
import { GUEST_SH, MOUNT_RUNNER_SH, NAMESPACE_SETUP_SH } from "../src/fence-assets"

// An isolated tmpdir so buildFenceCommand and sweepFenceDirs never see the
// host's real temp content.
const TEST_TMP = `/tmp/opencode/fence-test-${process.pid}`
const ORIGINAL_TMPDIR = process.env.TMPDIR

beforeAll(async () => {
  await fsPromises.mkdir(TEST_TMP, { recursive: true })
  process.env.TMPDIR = TEST_TMP
})

afterAll(async () => {
  process.env.TMPDIR = ORIGINAL_TMPDIR
  await fsPromises.rm(TEST_TMP, { recursive: true, force: true }).catch(() => {})
})

const fakeResolve4: Resolve4 = async (name) => {
  if (name === "registry.npmjs.org") return ["104.16.0.34", "104.16.1.34", "104.16.0.34"]
  if (name === "pypi.org") return ["151.101.0.223"]
  if (name === "unresolvable.invalid") throw new Error("ENOTFOUND")
  if (name === "empty.invalid") return []
  return []
}

describe("parseFenceEntry", () => {
  test("classifies IPv4 literals as networks", () => {
    expect(parseFenceEntry("10.17.146.234")).toEqual({ kind: "network", value: "10.17.146.234" })
  })

  test("classifies IPv4 CIDRs as networks", () => {
    expect(parseFenceEntry("10.16.59.0/24")).toEqual({ kind: "network", value: "10.16.59.0/24" })
    expect(parseFenceEntry(" 10.22.86.0/24 ")).toEqual({ kind: "network", value: "10.22.86.0/24" })
  })

  test("rejects invalid IPv4 and prefix", () => {
    expect(parseFenceEntry("256.1.1.1").kind).toBe("skip")
    expect(parseFenceEntry("10.0.0.0/33").kind).toBe("skip")
    expect(parseFenceEntry("10.0.0/24").kind).toBe("skip")
  })

  test("skips wildcards (v1 has no wildcard pinning)", () => {
    const entry = parseFenceEntry("*.github.com")
    expect(entry.kind).toBe("skip")
    if (entry.kind === "skip") expect(entry.reason).toContain("wildcard")
  })

  test("skips port-suffixed entries (v1 allows whole destinations)", () => {
    const entry = parseFenceEntry("example.com:8080")
    expect(entry.kind).toBe("skip")
    if (entry.kind === "skip") expect(entry.reason).toContain("port-suffixed")
  })

  test("skips IPv6", () => {
    for (const v6 of ["::1", "2001:db8::1", "fe80::1"]) {
      const entry = parseFenceEntry(v6)
      expect(entry.kind).toBe("skip")
      if (entry.kind === "skip") expect(entry.reason).toContain("IPv6")
    }
  })

  test("classifies hostnames as domains, lowercased", () => {
    expect(parseFenceEntry("registry.npmjs.org")).toEqual({
      kind: "domain",
      name: "registry.npmjs.org",
    })
    expect(parseFenceEntry("REGISTRY.NPMJS.ORG")).toEqual({
      kind: "domain",
      name: "registry.npmjs.org",
    })
    expect(parseFenceEntry("github.com")).toEqual({ kind: "domain", name: "github.com" })
    // Labels may end in any digit (first and non-first positions).
    expect(parseFenceEntry("a1.com")).toEqual({ kind: "domain", name: "a1.com" })
    expect(parseFenceEntry("v2.api2.pypi.org")).toEqual({
      kind: "domain",
      name: "v2.api2.pypi.org",
    })
  })

  test("rejects malformed hostnames and empties", () => {
    expect(parseFenceEntry("").kind).toBe("skip")
    expect(parseFenceEntry("   ").kind).toBe("skip")
    expect(parseFenceEntry("bad host.com").kind).toBe("skip")
    expect(parseFenceEntry("-leading.com").kind).toBe("skip")
    expect(parseFenceEntry("trailing-.com").kind).toBe("skip")
    expect(parseFenceEntry("a..b").kind).toBe("skip")
  })
})

describe("parseFenceAllowlist", () => {
  test("splits into pins, networks, and skips", async () => {
    const parsed = await parseFenceAllowlist(
      [
        "registry.npmjs.org",
        "pypi.org",
        "10.16.59.0/24",
        "10.17.146.234",
        "*.github.com",
        "unresolvable.invalid",
        "empty.invalid",
        "::1",
      ],
      fakeResolve4,
    )
    expect(parsed.pins).toEqual([
      { name: "registry.npmjs.org", ips: ["104.16.0.34", "104.16.1.34"] },
      { name: "pypi.org", ips: ["151.101.0.223"] },
    ])
    expect(parsed.networks).toEqual(["10.16.59.0/24", "10.17.146.234"])
    const skipEntries = parsed.skips.map((s) => s.entry)
    expect(skipEntries).toEqual(["*.github.com", "unresolvable.invalid", "empty.invalid", "::1"])
  })

  test("dedupes repeated domains (one resolution each) and networks", async () => {
    let calls = 0
    const counting: Resolve4 = async (name) => {
      calls++
      return fakeResolve4(name)
    }
    const parsed = await parseFenceAllowlist(
      ["pypi.org", "pypi.org", "pypi.org", "10.16.59.0/24", "10.16.59.0/24"],
      counting,
    )
    expect(calls).toBe(1)
    expect(parsed.pins).toHaveLength(1)
    expect(parsed.networks).toEqual(["10.16.59.0/24"])
  })

  test("an empty allowlist yields an empty fence (fail-closed)", async () => {
    const parsed = await parseFenceAllowlist([], fakeResolve4)
    expect(parsed).toEqual({ pins: [], networks: [], skips: [] })
  })
})

describe("fenceCapabilityFix", () => {
  // bwrap runs as guest root inside the pasta namespace; its
  // `--unshare-user --cap-drop ALL` would leave the seccomp helper unable to
  // map uid 0 in its nested user namespace (kernels >= 5.12 require
  // CAP_SETFCAP in the creator's bounding set). The fix mirrors what the
  // runtime itself does for uid-0 callers (capabilityArgs).
  test("injects --cap-add CAP_SETFCAP right after --cap-drop ALL", () => {
    const wrapped =
      "bwrap --new-session --die-with-parent --ro-bind / / --unshare-user --cap-drop ALL --proc /proc -- /bin/bash -c 'echo hi'"
    expect(fenceCapabilityFix(wrapped)).toBe(
      "bwrap --new-session --die-with-parent --ro-bind / / --unshare-user --cap-drop ALL --cap-add CAP_SETFCAP --proc /proc -- /bin/bash -c 'echo hi'",
    )
  })

  test("works in the --args-file rendered form too", () => {
    const wrapped =
      'sh -c "exec 9<$1 && shift && exec $@" srt-args /proc/42/fd/9 bwrap --new-session --args 9 --unshare-user --cap-drop ALL --proc /proc -- /bin/bash -c true'
    expect(fenceCapabilityFix(wrapped)).toContain("--cap-drop ALL --cap-add CAP_SETFCAP --proc")
  })

  test("does not double-inject when the cap is already present", () => {
    const wrapped = "bwrap --cap-drop ALL --cap-add CAP_SETFCAP -- true"
    expect(fenceCapabilityFix(wrapped)).toBe(wrapped)
  })

  test("ignores the cap words in the user command payload", () => {
    // The payload may contain the flag text itself (e.g. a commit message
    // documenting this fix); only the flag adjacent to the first
    // --cap-drop ALL counts, so the injection must still happen.
    const wrapped =
      "bwrap --cap-drop ALL -- /bin/bash -c 'echo --cap-add CAP_SETFCAP after --cap-drop ALL'"
    expect(fenceCapabilityFix(wrapped)).toBe(
      "bwrap --cap-drop ALL --cap-add CAP_SETFCAP -- /bin/bash -c 'echo --cap-add CAP_SETFCAP after --cap-drop ALL'",
    )
  })

  test("leaves a command without --cap-drop ALL untouched", () => {
    const wrapped = "bwrap --ro-bind / / -- /bin/bash -c 'echo hi'"
    expect(fenceCapabilityFix(wrapped)).toBe(wrapped)
  })

  test("injects at the FIRST occurrence (bwrap flags precede the user command)", () => {
    // A user command that happens to mention the flag stays verbatim.
    const wrapped = "bwrap --cap-drop ALL -- /bin/bash -c 'grep --cap-drop ALL file'"
    expect(fenceCapabilityFix(wrapped)).toBe(
      "bwrap --cap-drop ALL --cap-add CAP_SETFCAP -- /bin/bash -c 'grep --cap-drop ALL file'",
    )
  })
})

describe("buildFenceCommand", () => {
  test("assembles the scratch dir and the pasta invocation", async () => {
    const { command, dir } = await buildFenceCommand(
      "/usr/bin/bwrap --ro-bind / / -- /bin/bash -c 'echo hi'",
      ["registry.npmjs.org", "10.16.59.0/24", "*.github.com"],
      { resolve4: fakeResolve4, warn: () => {} },
    )
    try {
      expect(command).toBe(
        `pasta ${PASTA_FENCE_OPTIONS.join(" ")} --runas '${os.userInfo().username}' /usr/bin/bash '${path.join(dir, "guest.sh")}'`,
      )

      const files = await fsPromises.readdir(dir)
      for (const name of [
        "egress-responder.py",
        "guest.sh",
        "setup.sh",
        "runner.sh",
        "resolv.conf",
        "nsswitch.conf",
        "pin.txt",
        "nft.rules",
        "wrapped.sh",
      ])
        expect(files).toContain(name)

      // The name gate: pinned names + resolved IPs.
      expect(await fsPromises.readFile(path.join(dir, "pin.txt"), "utf8")).toBe(
        "registry.npmjs.org 104.16.0.34 104.16.1.34\n",
      )

      // The IP backstop: policy drop, dns endpoint, pinned IPs, CIDRs.
      const rules = await fsPromises.readFile(path.join(dir, "nft.rules"), "utf8")
      // inet: the policy drop covers IPv6 as well.
      expect(rules).toContain("add table inet egress")
      expect(rules).not.toContain("table ip ")
      expect(rules).toContain("policy drop")
      expect(rules).toContain("oifname lo accept")
      expect(rules).toContain("ip daddr 10.9.9.2 udp dport 53 accept")
      expect(rules).toContain("ct state established,related accept")
      expect(rules).toContain("ip daddr 104.16.0.34 accept")
      expect(rules).toContain("ip daddr 104.16.1.34 accept")
      expect(rules).toContain("ip daddr 10.16.59.0/24 accept")
      // Nothing may leak into the ruleset: the wildcard was skipped.
      expect(rules).not.toContain("github")

      // Resolver + NSS overrides for the mount ns.
      expect(await fsPromises.readFile(path.join(dir, "resolv.conf"), "utf8")).toBe(
        "nameserver 10.9.9.2\n",
      )
      expect(await fsPromises.readFile(path.join(dir, "nsswitch.conf"), "utf8")).toContain(
        "hosts: files dns",
      )

      // The wrapped command is embedded verbatim as the sh script body.
      const wrappedSh = await fsPromises.readFile(path.join(dir, "wrapped.sh"), "utf8")
      expect(wrappedSh).toBe(
        "#!/bin/sh\nexec /usr/bin/bwrap --ro-bind / / -- /bin/bash -c 'echo hi'\n",
      )

      // The responder asset is copied byte-exact.
      const responder = await fsPromises.readFile(path.join(dir, "egress-responder.py"))
      const source = await fsPromises.readFile(
        path.join(import.meta.dirname, "..", "src", "fence", "egress-responder.py"),
      )
      expect(responder.equals(source)).toBe(true)

      // The static scripts are byte-exact templates: no shell brace
      // interpolation could have been swallowed by the JS template literal.
      for (const script of [
        await fsPromises.readFile(path.join(dir, "guest.sh"), "utf8"),
        await fsPromises.readFile(path.join(dir, "setup.sh"), "utf8"),
        await fsPromises.readFile(path.join(dir, "runner.sh"), "utf8"),
      ]) {
        expect(script).not.toContain("`")
        expect(script).not.toContain("${")
      }
      expect(GUEST_SH).toContain("10.9.9.1/30")
      expect(NAMESPACE_SETUP_SH).toContain("10.9.9.2")
    } finally {
      await fsPromises.rm(dir, { recursive: true, force: true }).catch(() => {})
    }
  })

  test("warns about every skipped entry", async () => {
    const warnings: string[] = []
    const { dir } = await buildFenceCommand(
      "/usr/bin/bwrap -- true",
      ["*.example.org", "bad host", "unresolvable.invalid", "::1"],
      { resolve4: fakeResolve4, warn: (m) => warnings.push(m) },
    )
    try {
      expect(warnings).toHaveLength(4)
      expect(warnings.join("\n")).toContain("wildcard")
      expect(warnings.join("\n")).toContain("not a valid hostname")
      expect(warnings.join("\n")).toContain("resolution failed")
      expect(warnings.join("\n")).toContain("IPv6")
      // Nothing pinned: the responder sinkholes every name; the ruleset still
      // carries the fixed (dns endpoint / loopback / established) rules.
      expect(await fsPromises.readFile(path.join(dir, "pin.txt"), "utf8")).toBe("")
      const rules = await fsPromises.readFile(path.join(dir, "nft.rules"), "utf8")
      expect(rules).toContain("policy drop")
      expect(rules).toContain("ip daddr 10.9.9.2 udp dport 53 accept")
    } finally {
      await fsPromises.rm(dir, { recursive: true, force: true }).catch(() => {})
    }
  })
  test("honors the denylist: denied names are not pinned, denied IPs dropped first", async () => {
    const warnings: string[] = []
    const { dir } = await buildFenceCommand(
      "/usr/bin/bwrap -- true",
      ["registry.npmjs.org", "pypi.org", "10.0.0.0/8"],
      {
        denylist: ["PyPI.org", "*.npmjs.org", "10.1.2.3", "::1"],
        resolve4: fakeResolve4,
        warn: (m) => warnings.push(m),
      },
    )
    try {
      expect(await fsPromises.readFile(path.join(dir, "pin.txt"), "utf8")).toBe("")
      const rules = (await fsPromises.readFile(path.join(dir, "nft.rules"), "utf8")).split("\n")
      const drop = rules.indexOf("add rule inet egress output ip daddr 10.1.2.3 drop")
      const accept = rules.indexOf("add rule inet egress output ip daddr 10.0.0.0/8 accept")
      expect(drop).toBeGreaterThan(-1)
      expect(accept).toBeGreaterThan(drop)
      expect(warnings).toEqual([expect.stringContaining("ignoring denylist entry ::1")])
    } finally {
      await fsPromises.rm(dir, { recursive: true, force: true }).catch(() => {})
    }
  })

  test("applies the guest-root capability fix to the wrapped.sh body", async () => {
    const wrapped =
      "bwrap --new-session --die-with-parent --ro-bind / / --dev /dev --unshare-pid --unshare-user --cap-drop ALL --proc /proc --unsetenv SRT_ALLOW_NESTED_USERNS -- /bin/bash -c 'SRT_ALLOW_NESTED_USERNS=0 /x/apply-seccomp /bin/bash -c echo'"
    const { dir } = await buildFenceCommand(wrapped, ["pypi.org"], {
      resolve4: fakeResolve4,
      warn: () => {},
    })
    try {
      const wrappedSh = await fsPromises.readFile(path.join(dir, "wrapped.sh"), "utf8")
      expect(wrappedSh).toContain("--cap-drop ALL --cap-add CAP_SETFCAP --proc /proc")
      // The seccomp helper line itself is untouched.
      expect(wrappedSh).toContain("SRT_ALLOW_NESTED_USERNS=0 /x/apply-seccomp /bin/bash -c echo")
    } finally {
      await fsPromises.rm(dir, { recursive: true, force: true }).catch(() => {})
    }
  })
})

describe("fenceCommand", () => {
  test("single-quotes the guest path and username", () => {
    expect(fenceCommand("/tmp/opencode-fence-abc")).toBe(
      `pasta ${PASTA_FENCE_OPTIONS.join(" ")} --runas '${os.userInfo().username}' /usr/bin/bash '/tmp/opencode-fence-abc/guest.sh'`,
    )
    // The splice idiom: close the quote, an escaped literal quote, reopen.
    // ('o''connor' would parse as the bare word oconnor — wrong.)
    expect(fenceCommand("/tmp/x", "o'connor")).toContain(
      "--runas 'o'\\''connor' /usr/bin/bash '/tmp/x/guest.sh'",
    )
  })

  test("closes pasta's default holes and leaves stderr alone", () => {
    const command = fenceCommand("/tmp/opencode-fence-abc")
    // No host-loopback forwarding (-T/-U auto) and no inbound forwarding.
    for (const flag of ["-T none", "-U none", "-t none", "-u none"]) expect(command).toContain(flag)
    expect(command).toContain("--no-map-gw")
    expect(command).toContain("--ipv4-only")
    // The fence brings its own resolver; pasta must not look for the host's
    // (a loopback resolver is unreachable with --no-map-gw: warning per command).
    expect(command).toContain("--dns none")
    // Info chatter is suppressed by pasta itself; a redirect would also
    // capture the command's own stderr (the guest inherits pasta's stdio).
    expect(command).toContain("--quiet")
    expect(command).not.toContain("2>")
    expect(command.split("\n")).toHaveLength(1)
  })
})

describe("fenceDependenciesMissing", () => {
  test("reports the tools absent from PATH", async () => {
    const bin = `${TEST_TMP}/bin`
    await fsPromises.mkdir(bin, { recursive: true })
    for (const name of [...FENCE_DEPENDENCIES, "python3"]) {
      const p = path.join(bin, name)
      await fsPromises.writeFile(p, "#!/bin/sh\nexit 0\n")
      fs.chmodSync(p, 0o755)
    }
    const interpreter = path.join(bin, "python3")
    expect(fenceDependenciesMissing(bin, [interpreter])).toEqual([])
    await fsPromises.rm(path.join(bin, "nft"))
    expect(fenceDependenciesMissing(bin, [interpreter])).toEqual(["nft"])
    // Absolute interpreters are checked by path, not looked up in PATH.
    await fsPromises.rm(interpreter)
    expect(fenceDependenciesMissing(bin, [interpreter])).toEqual(["nft", interpreter])
    await fsPromises.rm(bin, { recursive: true, force: true })
  })
})

describe("parseFenceDenylist", () => {
  test("splits names, wildcard suffixes, networks, and skips", () => {
    const denied = parseFenceDenylist(["Evil.com", "*.corp.local", "10.1.0.0/16", "x.com:22"])
    expect([...denied.names]).toEqual(["evil.com"])
    expect(denied.suffixes).toEqual([".corp.local"])
    expect(denied.networks).toEqual(["10.1.0.0/16"])
    expect(denied.skips.map((s) => s.entry)).toEqual(["x.com:22"])
  })
})

describe("runsWithNoNewPrivs", () => {
  test("reads the NoNewPrivs flag from a status file", async () => {
    const status = path.join(TEST_TMP, "status")
    await fsPromises.writeFile(status, "Name:\tx\nNoNewPrivs:\t1\nSeccomp:\t2\n")
    expect(runsWithNoNewPrivs(status)).toBe(true)
    await fsPromises.writeFile(status, "Name:\tx\nNoNewPrivs:\t0\n")
    expect(runsWithNoNewPrivs(status)).toBe(false)
    expect(runsWithNoNewPrivs(path.join(TEST_TMP, "missing"))).toBe(false)
  })
})

describe("egress-responder", () => {
  test("answers pinned names and NXDOMAINs everything else", async () => {
    if (!fs.existsSync("/usr/bin/python3")) return
    const pin = path.join(TEST_TMP, "pin-responder.txt")
    await fsPromises.writeFile(pin, "example.com 93.184.215.14\n")
    const port = 20000 + (process.pid % 20000)
    const script = path.join(import.meta.dirname, "..", "src", "fence", "egress-responder.py")
    const child = Bun.spawn(["/usr/bin/python3", script, String(port), pin, "127.0.0.1"], {
      stderr: "pipe",
    })
    try {
      // Wait for the readiness line the guest also waits for.
      const reader = child.stderr.getReader()
      const { value } = await reader.read()
      expect(new TextDecoder().decode(value)).toStartWith("responder listening")
      const query = (name: string, qtype: number) => {
        const labels = name.split(".").flatMap((l) => [l.length, ...Buffer.from(l)])
        return Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...labels, 0, 0, qtype, 0, 1])
      }
      const ask = async (name: string, qtype: number) => {
        const { promise, resolve } = Promise.withResolvers<Buffer>()
        const socket = await Bun.udpSocket({
          socket: { data: (_s, data) => resolve(Buffer.from(data)) },
        })
        socket.send(query(name, qtype), port, "127.0.0.1")
        const reply = await promise
        socket.close()
        return { rcode: reply[3] & 0xf, answers: reply.readUInt16BE(6), tail: reply.subarray(-4) }
      }
      const allowed = await ask("example.com", 1)
      expect(allowed.rcode).toBe(0)
      expect(allowed.answers).toBe(1)
      expect([...allowed.tail]).toEqual([93, 184, 215, 14])
      // Not allowlisted: NXDOMAIN, no sinkhole address (0.0.0.0 is local).
      const blocked = await ask("evil.org", 1)
      expect(blocked.rcode).toBe(3)
      expect(blocked.answers).toBe(0)
    } finally {
      child.kill()
    }
  })
})

describe("sweepFenceDirs", () => {
  test("removes only stale fence entries (dirs and pasta-stderr files)", async () => {
    const old = path.join(TEST_TMP, `${FENCE_DIR_PREFIX}old`)
    const fresh = path.join(TEST_TMP, `${FENCE_DIR_PREFIX}fresh`)
    const other = path.join(TEST_TMP, "unrelated-dir")
    for (const p of [old, fresh, other]) await fsPromises.mkdir(p, { recursive: true })
    // per-command pasta-stderr file: stale one must go, fresh one stays
    const oldErr = path.join(TEST_TMP, `${FENCE_DIR_PREFIX}pasta-old.err`)
    const freshErr = path.join(TEST_TMP, `${FENCE_DIR_PREFIX}pasta-fresh.err`)
    for (const p of [oldErr, freshErr]) await fsPromises.writeFile(p, "noise")
    const past = new Date(Date.now() - 3 * 60 * 60 * 1000)
    for (const p of [old, oldErr]) await fsPromises.utimes(p, past, past)

    const removed = await sweepFenceDirs(TEST_TMP, 2 * 60 * 60 * 1000)

    expect(removed).toBe(2)
    expect(await fsPromises.stat(old).catch(() => null)).toBeNull()
    expect(await fsPromises.stat(oldErr).catch(() => null)).toBeNull()
    expect((await fsPromises.stat(fresh)).isDirectory()).toBe(true)
    expect((await fsPromises.stat(freshErr)).isFile()).toBe(true)
    expect((await fsPromises.stat(other)).isDirectory()).toBe(true)
    await fsPromises.rm(fresh, { recursive: true, force: true })
    await fsPromises.rm(freshErr, { force: true })
    await fsPromises.rm(other, { recursive: true, force: true })
  })
})

// The static scripts are the load-bearing part of the fence; sanity-check the
// invariants that make them safe to exec byte-for-byte.
describe("fence-assets invariants", () => {
  test("scripts carry no template interpolation or backticks", () => {
    for (const script of [GUEST_SH, NAMESPACE_SETUP_SH, MOUNT_RUNNER_SH]) {
      expect(script).not.toContain("`")
      expect(script).not.toContain("${")
      expect(script.startsWith("#!/bin/bash")).toBe(true)
    }
  })

  test("the veth wiring is consistent across the scripts", () => {
    expect(GUEST_SH).toContain("ip link add dns0 type veth peer name dns1")
    expect(GUEST_SH).toContain("ip addr add 10.9.9.1/30 dev dns0")
    // Readiness is awaited, not slept for; a failed veth move is fatal, and
    // the move waits for the child's own netns (else it is a silent no-op).
    expect(GUEST_SH).toContain('grep -q "^responder listening"')
    expect(GUEST_SH).not.toContain("sleep 1.5")
    expect(GUEST_SH).toContain('fail "moving the dns veth peer')
    expect(GUEST_SH).toContain('[ "$CHILD_NS" != "$SELF_NS" ]')
    expect(NAMESPACE_SETUP_SH).toContain('ip addr add "$DNS_IP"/30 dev "$IF"')
    expect(MOUNT_RUNNER_SH).toContain('mount --bind "$DIR/resolv.conf"')
    expect(MOUNT_RUNNER_SH).toContain('exec /bin/sh "$DIR/wrapped.sh"')
  })
})
