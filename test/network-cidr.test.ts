/**
 * Guardrail for the local patch against @anthropic-ai/sandbox-runtime
 * (patches/@anthropic-ai+sandbox-runtime+0.0.81.patch), which adds
 * IP-literal / CIDR support to network.allowedDomains and network.deniedDomains
 * — the upstream RFE is tracked at
 * https://github.com/anthropics/sandbox-runtime/issues/65.
 *
 * The imports point at the installed dist files on purpose: if the patch is
 * missing (fresh install without postinstall, or an SRT version bump), the
 * schema assertions below fail and make the gap visible instead of letting
 * CIDR entries be silently dropped or rejected at sandbox start.
 */
import { describe, expect, test } from "bun:test"
import {
  ipLiteralRules,
  matchesDomainPattern,
  matchesDomainPatternWithPort,
} from "../node_modules/@anthropic-ai/sandbox-runtime/dist/sandbox/domain-pattern.js"
import { createResolvedAddressGuard } from "../node_modules/@anthropic-ai/sandbox-runtime/dist/sandbox/resolved-address-guard.js"
import { NetworkConfigSchema } from "../node_modules/@anthropic-ai/sandbox-runtime/dist/sandbox/sandbox-config.js"

const networkOk = (allowedDomains: string[] = [], deniedDomains: string[] = []) =>
  NetworkConfigSchema.safeParse({ allowedDomains, deniedDomains }).success

describe("patched SRT schema accepts CIDR entries", () => {
  test("allowedDomains accepts IP literals and CIDR ranges", () => {
    expect(networkOk(["10.22.86.0/24"])).toBe(true)
    expect(networkOk(["10.22.86.5"])).toBe(true)
    expect(networkOk(["10.22.86.0/24:8080"])).toBe(true)
    expect(networkOk(["2001:db8::/32"])).toBe(true)
    expect(networkOk(["2001:db8::1"])).toBe(true)
    expect(networkOk(["[2001:db8::1]"])).toBe(true)
    expect(networkOk(["github.com", "10.22.86.0/24"])).toBe(true)
  })

  test("deniedDomains accepts CIDR ranges (deny-all stays valid)", () => {
    expect(networkOk([], ["10.0.0.0/8"])).toBe(true)
    expect(networkOk([], ["*"])).toBe(true)
  })

  test("still rejects malformed entries and broad wildcards", () => {
    expect(networkOk(["evil.com/24"])).toBe(false)
    expect(networkOk(["10.0.0.0/33"])).toBe(false)
    expect(networkOk(["2001:db8::/129"])).toBe(false)
    expect(networkOk(["[2001:db8::]/32"])).toBe(false)
    expect(networkOk(["10.22.86.0/24junk"])).toBe(false)
    expect(networkOk(["*.10.0.0.0/8"])).toBe(false)
    expect(networkOk(["10.22.86.0/24:0"])).toBe(false)
    expect(networkOk(["*.com"])).toBe(false)
  })
})

describe("patched SRT matcher is CIDR-aware", () => {
  test("matches IP-literal destinations by range, with port semantics", () => {
    expect(matchesDomainPatternWithPort("10.22.86.5", 443, "10.22.86.0/24")).toBe(true)
    expect(matchesDomainPatternWithPort("10.22.86.5", 443, "10.22.86.0/24:8080")).toBe(false)
    expect(matchesDomainPatternWithPort("10.22.86.5", 8080, "10.22.86.0/24:8080")).toBe(true)
    expect(matchesDomainPatternWithPort("10.22.87.1", 443, "10.22.86.0/24")).toBe(false)
    // inet_aton shorthand (169236173 == 10.22.86.5) canonicalizes into the range
    expect(matchesDomainPatternWithPort("169236173", 443, "10.22.86.0/24")).toBe(true)
    expect(matchesDomainPattern("2001:db8::1", "2001:db8::/32")).toBe(true)
    expect(matchesDomainPattern("2001:db9::1", "2001:db8::/32")).toBe(false)
  })

  test("never matches names or the wrong direction", () => {
    expect(matchesDomainPattern("evil.com", "10.0.0.0/8")).toBe(false)
    expect(matchesDomainPattern("10.22.86.5", "evil.com")).toBe(false)
    // existing behavior is untouched
    expect(matchesDomainPatternWithPort("api.github.com", 443, "*.github.com")).toBe(true)
    expect(matchesDomainPattern("127.0.0.1", "127.0.0.1")).toBe(true)
  })

  test("ipLiteralRules feeds CIDR entries to the resolved-address guard", () => {
    const rules = ipLiteralRules(["10.22.86.0/24", "example.com", "[2001:db8::1]", "2001:db8::/32"])
    expect(rules).toHaveLength(3)
    expect(rules.some((r) => r.range === "10.22.86.0/24")).toBe(true)
    expect(rules.some((r) => r.range === "2001:db8::/32")).toBe(true)
  })
})

describe("patched resolved-address guard honors CIDR lists", () => {
  const fakeResolve =
    (answers: string[]) =>
    (
      _hostname: string,
      _options: object,
      callback: (err: null, addresses: { address: string; family: number }[]) => void,
    ) =>
      callback(
        null,
        answers.map((address) => ({ address, family: address.includes(":") ? 6 : 4 })),
      )

  test("a name resolving into a denied CIDR is refused", () => {
    const guard = createResolvedAddressGuard({
      allowedDomains: ["*.corp"],
      deniedDomains: ["10.22.86.0/24"],
      resolve: fakeResolve(["10.22.86.5"]),
    })
    expect(guard.permits("db.corp", "10.22.86.5", 443)).toBe(false)
    const other = createResolvedAddressGuard({
      allowedDomains: ["*.corp"],
      deniedDomains: ["10.22.86.0/24"],
      resolve: fakeResolve(["8.8.8.8"]),
    })
    expect(other.permits("db.corp", "8.8.8.8", 443)).toBe(true)
  })

  test("an allowed CIDR carves out a built-in denial, like IP literals do", () => {
    // without the allow entry, a name resolving to loopback is denied
    const plain = createResolvedAddressGuard({
      allowedDomains: [],
      deniedDomains: [],
      resolve: fakeResolve(["127.0.0.1"]),
    })
    expect(plain.permits("svc.internal", "127.0.0.1", 443)).toBe(false)
    // ...an explicit 127.0.0.0/8 allow entry lifts it, matching the
    // long-standing semantics for exact IP literals
    const carved = createResolvedAddressGuard({
      allowedDomains: ["127.0.0.0/8"],
      deniedDomains: [],
      resolve: fakeResolve(["127.0.0.1"]),
    })
    expect(carved.permits("svc.internal", "127.0.0.1", 443)).toBe(true)
  })
})
