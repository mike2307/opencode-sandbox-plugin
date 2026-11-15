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
  killProcessTree,
  PASTA_FENCE_OPTIONS,
  parseFenceAllowlist,
  parseFenceDenylist,
  parseFenceEntry,
  type Resolve4,
  releaseFenceDir,
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
  if (ORIGINAL_TMPDIR === undefined) delete process.env.TMPDIR
  else process.env.TMPDIR = ORIGINAL_TMPDIR
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

  test("parses *.domain wildcards; refuses over-broad and other star forms", () => {
    expect(parseFenceEntry("*.github.com")).toEqual({ kind: "wildcard", base: "github.com" })
    expect(parseFenceEntry("*.API.GitHub.COM")).toEqual({
      kind: "wildcard",
      base: "api.github.com",
    })
    const overbroad = parseFenceEntry("*.com")
    expect(overbroad.kind).toBe("skip")
    if (overbroad.kind === "skip") expect(overbroad.reason).toContain("overly broad")
    expect(parseFenceEntry("*").kind).toBe("skip")
    expect(parseFenceEntry("*x.com").kind).toBe("skip")
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
    expect(parsed.wildcards).toEqual(["github.com"])
    expect(parsed.networks).toEqual(["10.16.59.0/24", "10.17.146.234"])
    const skipEntries = parsed.skips.map((s) => s.entry)
    expect(skipEntries).toEqual(["unresolvable.invalid", "empty.invalid", "::1"])
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
    expect(parsed).toEqual({ pins: [], wildcards: [], networks: [], skips: [] })
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
      const lines = command.split("\n")
      // With a wildcard entry, the wrapper manages the upstream resolver:
      // start it, wait for readiness, run pasta, kill it, keep its exit code.
      expect(lines[0]).toContain("upstream-resolver.py")
      expect(lines[0]).toContain(`>'${path.join(dir, "up.log")}' 2>&1 &`)
      expect(lines[1]).toBe("UP_PID=$!")
      expect(lines).toContain(
        `  grep -q "^upstream listening" '${path.join(dir, "up.log")}' 2>/dev/null && { READY=1; break; }`,
      )
      // The pasta line itself stays clean: no stderr redirect (the guest
      // inherits pasta's stdio), no chatter.
      const pastaLine = lines.find((line) => line.startsWith("pasta")) as string
      expect(pastaLine).toBe(
        `pasta ${PASTA_FENCE_OPTIONS.join(" ")} --runas '${os.userInfo().username}' /usr/bin/bash '${path.join(dir, "guest.sh")}'`,
      )
      expect(pastaLine).not.toContain("2>")
      expect(lines[lines.length - 2]).toBe('kill "$UP_PID" 2>/dev/null')
      expect(lines[lines.length - 1]).toBe('exit "$rc"')

      const files = await fsPromises.readdir(dir)
      for (const name of [
        "egress-responder.py",
        "upstream-resolver.py",
        "fence-agent.py",
        "guest.sh",
        "setup.sh",
        "runner.sh",
        "resolv.conf",
        "nsswitch.conf",
        "pin.txt",
        "wildcards.txt",
        "nft.rules",
        "wrapped.sh",
      ])
        expect(files).toContain(name)

      // The name gate: pinned names + resolved IPs.
      expect(await fsPromises.readFile(path.join(dir, "pin.txt"), "utf8")).toBe(
        "registry.npmjs.org 104.16.0.34 104.16.1.34\n",
      )
      // Wildcard bases are written for the daemon/agent, not the ruleset.
      expect(await fsPromises.readFile(path.join(dir, "wildcards.txt"), "utf8")).toBe(
        "*.github.com\n",
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
      // Nothing may leak into the ruleset: the wildcard adds no static rule
      // (its subdomains are vouched into rules at runtime, per address).
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

      // The python assets are copied byte-exact.
      for (const asset of ["egress-responder.py", "upstream-resolver.py", "fence-agent.py"]) {
        const copied = await fsPromises.readFile(path.join(dir, asset))
        const source = await fsPromises.readFile(
          path.join(import.meta.dirname, "..", "src", "fence", asset),
        )
        expect(copied.equals(source)).toBe(true)
      }

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
      ["*.org", "bad host", "unresolvable.invalid", "::1"],
      { resolve4: fakeResolve4, warn: (m) => warnings.push(m) },
    )
    try {
      expect(warnings).toHaveLength(4)
      expect(warnings.join("\n")).toContain("overly broad")
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

  test("deniedDomains ['*'] unpins every domain but keeps raw IP entries", async () => {
    const { command, dir } = await buildFenceCommand(
      "/usr/bin/bwrap -- true",
      ["registry.npmjs.org", "*.github.com", "10.0.0.0/8"],
      { denylist: ["*"], resolve4: fakeResolve4, warn: () => {} },
    )
    try {
      expect(await fsPromises.readFile(path.join(dir, "pin.txt"), "utf8")).toBe("")
      // `*` denies names, wildcards included: no wildcard base, no daemon.
      expect(await fsPromises.readFile(path.join(dir, "wildcards.txt"), "utf8")).toBe("")
      expect(command).not.toContain("upstream-resolver.py")
      expect(await fsPromises.readFile(path.join(dir, "denied.txt"), "utf8")).toBe("*\n")
      expect(await fsPromises.readFile(path.join(dir, "nft.rules"), "utf8")).toContain(
        "add rule inet egress output ip daddr 10.0.0.0/8 accept",
      )
    } finally {
      await fsPromises.rm(dir, { recursive: true, force: true }).catch(() => {})
    }
  })

  test("hands name denials to the runtime wildcard lookups (denied.txt)", async () => {
    const { dir } = await buildFenceCommand(
      "/usr/bin/bwrap -- true",
      ["*.github.com", "*.evil.org"],
      {
        denylist: ["Evil.GitHub.com", "*.internal.github.com", "*.evil.org", "10.1.2.3"],
        resolve4: fakeResolve4,
        warn: () => {},
      },
    )
    try {
      // A wildcard covered by a denied wildcard is dropped up front...
      expect(await fsPromises.readFile(path.join(dir, "wildcards.txt"), "utf8")).toBe(
        "*.github.com\n",
      )
      // ...and names under a surviving wildcard are refused at lookup time.
      expect(await fsPromises.readFile(path.join(dir, "denied.txt"), "utf8")).toBe(
        "evil.github.com\n*.internal.github.com\n*.evil.org\n",
      )
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

  test("manages the upstream resolver when wildcard entries are present", () => {
    const command = fenceCommand("/tmp/opencode-fence-abc", "user", true)
    const lines = command.split("\n")
    // Daemon first: start, record the pid, wait for its readiness line.
    expect(lines[0]).toBe(
      `/usr/bin/python3 '/tmp/opencode-fence-abc/upstream-resolver.py' '/tmp/opencode-fence-abc' >'/tmp/opencode-fence-abc/up.log' 2>&1 &`,
    )
    expect(lines[1]).toBe("UP_PID=$!")
    expect(lines[2]).toBe("echo \"$UP_PID\" >'/tmp/opencode-fence-abc/upstream.pid'")
    expect(lines.some((l) => l.includes('grep -q "^upstream listening"'))).toBe(true)
    // Fail closed when the daemon does not come up.
    expect(lines).toContain(
      '  echo "opencode-sandbox fence: the upstream resolver did not come up:" >&2',
    )
    expect(lines).toContain("  exit 1")
    // The pasta line is untouched (no stderr redirect of its own); the
    // daemon is killed after, and pasta's exit status is preserved.
    const pastaIdx = lines.findIndex((l) => l.startsWith("pasta"))
    expect(lines[pastaIdx]).toBe(
      `pasta ${PASTA_FENCE_OPTIONS.join(" ")} --runas 'user' /usr/bin/bash '/tmp/opencode-fence-abc/guest.sh'`,
    )
    expect(lines[pastaIdx + 1]).toBe("rc=$?")
    expect(lines[lines.length - 2]).toBe('kill "$UP_PID" 2>/dev/null')
    expect(lines[lines.length - 1]).toBe('exit "$rc"')
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
    expect(denied.allNames).toBe(false)
    expect(denied.skips.map((s) => s.entry)).toEqual(["x.com:22"])
  })
  test("treats '*' as deny-all names, not as a skip", () => {
    const denied = parseFenceDenylist(["*"])
    expect(denied.allNames).toBe(true)
    expect(denied.names).toEqual(new Set())
    expect(denied.skips).toEqual([])
  })
})

describe("killProcessTree", () => {
  const descendantsOf = (root: number): number[] => {
    const byParent = new Map<number, number[]>()
    for (const name of fs.readdirSync("/proc")) {
      if (!/^\d+$/.test(name)) continue
      const pid = Number(name)
      if (pid === root) continue
      try {
        const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8")
        const ppid = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1])
        if (Number.isInteger(ppid)) byParent.set(ppid, [...(byParent.get(ppid) ?? []), pid])
      } catch {
        // gone mid-scan
      }
    }
    const out: number[] = []
    const stack = [root]
    while (stack.length > 0) {
      const pid = stack.pop() as number
      for (const child of byParent.get(pid) ?? []) {
        out.push(child)
        stack.push(child)
      }
    }
    return out
  }

  test("kills the descendants, not just the root", async () => {
    if (process.platform !== "linux") return
    const child = Bun.spawn(["/bin/sh", "-c", "sleep 60 & sleep 60 & wait"], {
      stdout: "ignore",
      stderr: "ignore",
    })
    try {
      // Wait for both grandchildren to show up under the shell.
      for (let i = 0; i < 100 && descendantsOf(child.pid as number).length < 2; i++)
        await new Promise((resolve) => setTimeout(resolve, 20))
      const doomed = descendantsOf(child.pid as number)
      expect(doomed).toHaveLength(2)
      killProcessTree(child.pid as number)
      // Everyone below the root is gone, and so is the root.
      for (let i = 0; i < 100; i++) {
        if (
          !fs.existsSync(`/proc/${child.pid}`) &&
          doomed.every((pid) => !fs.existsSync(`/proc/${pid}`))
        )
          return
        await new Promise((resolve) => setTimeout(resolve, 20))
      }
      const alive = [child.pid, ...doomed].filter((pid) => fs.existsSync(`/proc/${pid}`))
      expect(alive).toEqual([])
    } finally {
      child.kill()
    }
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

// AF_UNIX may be unavailable where the tests run (the sandbox-runtime
// seccomp filter blocks socket(AF_UNIX) for processes inside bwrap — which is
// where agent commands, and often dev sessions, execute). The fence's own
// components run OUTSIDE bwrap, where unix sockets are fine.
let unixAvail: boolean | undefined
const unixSocketsAvailable = async () => {
  if (unixAvail !== undefined) return unixAvail
  if (!fs.existsSync("/usr/bin/python3")) {
    unixAvail = false
    return unixAvail
  }
  const p = Bun.spawn(
    [
      "/usr/bin/python3",
      "-c",
      "import socket; socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).close(); print('ok')",
    ],
    { stdout: "pipe", stderr: "ignore" },
  )
  let out = ""
  const reader = p.stdout.getReader()
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    out += new TextDecoder().decode(value)
  }
  await p.exited
  unixAvail = out.includes("ok")
  return unixAvail
}

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

  test("vouches wildcard-matched names through the agent socket", async () => {
    if (!fs.existsSync("/usr/bin/python3") || !(await unixSocketsAvailable())) return
    const dir = path.join(TEST_TMP, "resp-wc")
    await fsPromises.mkdir(dir, { recursive: true })
    await fsPromises.writeFile(path.join(dir, "pin.txt"), "")
    await fsPromises.writeFile(path.join(dir, "wildcards.txt"), "*.invalid\n")
    await fsPromises.writeFile(path.join(dir, "denied.txt"), "blocked.invalid\n")
    // Fake agent: answers every request with one fixed address.
    const fakeAgent = [
      "import socket, sys, os",
      "p = sys.argv[1]",
      "try: os.unlink(p)",
      "except OSError: pass",
      "s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(p); s.listen(1)",
      "sys.stderr.write('fake-agent up\\n'); sys.stderr.flush()",
      "while True:",
      "    c, _ = s.accept()",
      "    f = c.makefile('rb')",
      "    while True:",
      "        line = f.readline()",
      "        if not line: break",
      "        c.sendall(b'0\\t93.184.215.16\\n')",
      "    c.close()",
    ].join("\n")
    const agent = Bun.spawn(["/usr/bin/python3", "-c", fakeAgent, path.join(dir, "agent.sock")], {
      stderr: "pipe",
    })
    const port = 20000 + (process.pid % 20000)
    const script = path.join(import.meta.dirname, "..", "src", "fence", "egress-responder.py")
    const child = Bun.spawn(
      ["/usr/bin/python3", script, String(port), path.join(dir, "pin.txt"), "127.0.0.1"],
      { stderr: "pipe" },
    )
    try {
      const agentLine = await agent.stderr.getReader().read()
      expect(new TextDecoder().decode(agentLine.value as Uint8Array)).toStartWith("fake-agent up")
      const respLine = await child.stderr.getReader().read()
      expect(new TextDecoder().decode(respLine.value as Uint8Array)).toStartWith(
        "responder listening",
      )
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
      // A strict subdomain of the wildcard base is answered (by the agent).
      const vouched = await ask("unit-test.invalid", 1)
      expect(vouched.rcode).toBe(0)
      expect(vouched.answers).toBe(1)
      expect([...vouched.tail]).toEqual([93, 184, 215, 16])
      // The base itself is not a subdomain: NXDOMAIN.
      const base = await ask("invalid", 1)
      expect(base.rcode).toBe(3)
      // An unrelated name: NXDOMAIN.
      const other = await ask("evil.org", 1)
      expect(other.rcode).toBe(3)
      // A denied subdomain: NXDOMAIN although the agent would vouch for it.
      const denied = await ask("blocked.invalid", 1)
      expect(denied.rcode).toBe(3)
      expect(denied.answers).toBe(0)
    } finally {
      child.kill()
      agent.kill()
      await fsPromises.rm(dir, { recursive: true, force: true }).catch(() => {})
    }
  })
})

describe("upstream-resolver", () => {
  test("answers only wildcard-matched names, refusing the rest", async () => {
    if (!fs.existsSync("/usr/bin/python3") || !(await unixSocketsAvailable())) return
    const dir = path.join(TEST_TMP, "upstream-test")
    await fsPromises.mkdir(dir, { recursive: true })
    await fsPromises.writeFile(path.join(dir, "wildcards.txt"), "*.invalid\n")
    await fsPromises.writeFile(path.join(dir, "denied.txt"), "blocked.invalid\n*.deep.invalid\n")
    const script = path.join(import.meta.dirname, "..", "src", "fence", "upstream-resolver.py")
    const child = Bun.spawn(["/usr/bin/python3", script, dir], { stderr: "pipe" })
    try {
      // Wait for the readiness line the fence wrapper also waits for.
      const { value } = await child.stderr.getReader().read()
      expect(new TextDecoder().decode(value)).toStartWith("upstream listening")
      const client = [
        "import socket, sys",
        "c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)",
        "c.connect(sys.argv[1])",
        "c.sendall((sys.argv[2] + ' ' + sys.argv[3] + '\\n').encode())",
        "print(c.makefile('rb').readline().decode().strip())",
        "c.close()",
      ].join("\n")
      const ask = async (name: string, qtype: string) => {
        const p = Bun.spawn(
          ["/usr/bin/python3", "-c", client, path.join(dir, "upstream.sock"), name, qtype],
          { stdout: "pipe", stderr: "ignore" },
        )
        let out = ""
        const reader = p.stdout.getReader()
        for (;;) {
          const { value, done } = await reader.read()
          if (done) break
          out += new TextDecoder().decode(value)
        }
        await p.exited
        return out.trim()
      }
      // Matches the wildcard base: hermetically NXDOMAIN (.invalid, RFC 2606).
      expect(await ask("unit-test.invalid", "1")).toBe("3\t")
      // Not a strict subdomain / not a wildcard at all: refused, never answered.
      expect(await ask("example.com", "1")).toBe("2\t")
      expect(await ask("invalid", "1")).toBe("2\t")
      // IPv4-only fence: AAAA is answered empty, never with v6 addresses.
      expect(await ask("unit-test.invalid", "28")).toBe("0\t")
      // Denied names (exact or by suffix) are NXDOMAIN before any lookup —
      // visible on AAAA, which an allowed name answers with "0".
      expect(await ask("blocked.invalid", "28")).toBe("3\t")
      expect(await ask("x.deep.invalid", "28")).toBe("3\t")
    } finally {
      child.kill()
      await fsPromises.rm(dir, { recursive: true, force: true }).catch(() => {})
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

  test("the wildcard agent is gated on wildcards.txt and cleaned up", () => {
    // The agent (in-netns rule writer) starts only with wildcard entries and
    // is killed by both the fail and the normal-exit paths.
    expect(GUEST_SH).toContain('[ -s "$DIR/wildcards.txt" ]')
    expect(GUEST_SH).toContain('$DIR/fence-agent.py" "$DIR"')
    expect(GUEST_SH).toContain("AGENT_PID=$!")
    // kill "$AGENT_PID" appears in fail() and in the final cleanup.
    expect(GUEST_SH.match(/kill "\$AGENT_PID" 2>\/dev\/null/g)?.length).toBe(2)
    // Its readiness is awaited (a lookup before it listens would fail), and
    // an agent that never comes up is fatal.
    expect(GUEST_SH).toContain('grep -q "^agent listening"')
    expect(GUEST_SH).toContain('fail "wildcard agent failed"')
    expect(GUEST_SH.indexOf('grep -q "^agent listening"')).toBeLessThan(
      GUEST_SH.indexOf("unshare --mount"),
    )
  })
})

describe("releaseFenceDir", () => {
  const sleeper = (...extra: string[]) =>
    Bun.spawn(["/usr/bin/python3", "-c", "import time; time.sleep(30)", ...extra])

  test("terminates this dir's resolver, never an unrelated process", async () => {
    if (!fs.existsSync("/usr/bin/python3") || !fs.existsSync("/proc/self/cmdline")) return
    const dir = path.join(TEST_TMP, `${FENCE_DIR_PREFIX}release`)
    const other = path.join(TEST_TMP, `${FENCE_DIR_PREFIX}release-other`)
    for (const d of [dir, other]) await fsPromises.mkdir(d, { recursive: true })
    // Stand-ins: one carries this dir's resolver path in its argv, the other
    // is an unrelated process that reused the recorded pid.
    const resolver = sleeper(path.join(dir, "upstream-resolver.py"))
    const unrelated = sleeper()
    try {
      await fsPromises.writeFile(path.join(other, "upstream.pid"), `${unrelated.pid}\n`)
      await releaseFenceDir(other)
      expect(fs.existsSync(other)).toBe(false)
      expect(unrelated.killed || unrelated.exitCode !== null).toBe(false)

      await fsPromises.writeFile(path.join(dir, "upstream.pid"), `${resolver.pid}\n`)
      await releaseFenceDir(dir)
      expect(fs.existsSync(dir)).toBe(false)
      expect(await resolver.exited).not.toBe(0)
    } finally {
      resolver.kill()
      unrelated.kill()
    }
  })
})
