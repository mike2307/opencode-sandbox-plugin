import { afterAll, beforeAll, beforeEach, describe, expect, mock, test } from "bun:test"
import fs from "node:fs"
import fsPromises from "node:fs/promises"
import os from "node:os"
import path from "node:path"

// mock.module is process-wide and live (it mutates the export bindings of
// already-imported modules, and in a shared, non-isolated `bun test` run it
// persists across test files). Snapshot the real modules eagerly — before any
// mock is installed — and restore them in afterAll below, so later test files
// that import src/fence.ts / src/probe.ts directly (test/fence.test.ts,
// test/probe.test.ts) still get the real modules regardless of file order.
const realFenceModule = { ...(await import("../src/fence")) }
const realProbeModule = { ...(await import("../src/probe")) }

// Mock the SandboxManager before importing the plugin
const mockInitialize = mock(() => Promise.resolve())
const mockWrapWithSandbox = mock((cmd: string) => Promise.resolve(`srt-wrapped: ${cmd}`))
const mockCleanupAfterCommand = mock(() => undefined)

mock.module("@anthropic-ai/sandbox-runtime", () => ({
  SandboxManager: {
    initialize: mockInitialize,
    wrapWithSandbox: mockWrapWithSandbox,
    cleanupAfterCommand: mockCleanupAfterCommand,
  },
}))

const mockRunEnforcementProbe = mock((_shell: string) => Promise.resolve())
mock.module("../src/probe", () => ({ runEnforcementProbe: mockRunEnforcementProbe }))

// Mock the fence (src/fence.ts): the plugin test asserts the wiring only —
// parsing, file assembly, and the pasta command shape live in test/fence.test.ts.
const FENCE_TEST_DIR = "/tmp/opencode-fence-plugin-test"
const FENCE_TEST_COMMAND = `pasta --config-net --runas test /usr/bin/bash '${FENCE_TEST_DIR}/guest.sh'`
const mockBuildFenceCommand = mock(
  (
    _wrapped: string,
    _allowlist: string[],
    _options?: { denylist?: string[]; warn?: (m: string) => void },
  ) => Promise.resolve({ command: FENCE_TEST_COMMAND, dir: FENCE_TEST_DIR }),
)
const mockFenceDependenciesMissing = mock(() => [] as string[])
const mockSweepFenceDirs = mock(() => Promise.resolve(0))
const mockRunFenceProbe = mock(() => Promise.resolve())
const mockReleaseFenceDir = mock((dir: string) =>
  fsPromises.rm(dir, { recursive: true, force: true }),
)
mock.module("../src/fence", () => ({
  buildFenceCommand: mockBuildFenceCommand,
  fenceDependenciesMissing: mockFenceDependenciesMissing,
  releaseFenceDir: mockReleaseFenceDir,
  runFenceProbe: mockRunFenceProbe,
  runsWithNoNewPrivs: () => false,
  sweepFenceDirs: mockSweepFenceDirs,
  FENCE_DIR_PREFIX: "opencode-fence-",
}))

// Mock the plugin SDK: define() is an identity function in tests
mock.module("@opencode/plugin", () => ({
  Plugin: { define: (plugin: unknown) => plugin },
}))

// Return the real modules to the registry: the partial mocks above only cover
// this file's plugin-wiring assertions. Without this restore, a later test
// file in the same process (test/fence.test.ts, test/probe.test.ts) would
// resolve its static imports against the partial mocks and fail on the
// missing exports.
afterAll(() => {
  mock.module("../src/fence", () => realFenceModule)
  mock.module("../src/probe", () => realProbeModule)
})

const pluginModule = await import("../src/index")
// Root index.ts is what OpenCode 2 loads for local path plugins; it must stay
// a working re-export of the server module.
const rootModule = await import("../index")

const toggleModule = await import("../src/toggle")

// Isolated cache dir so shim writes never touch the developer's real home
let testCacheHome: string | undefined
let isolatedCacheHome: string | undefined

const shimDir = () => path.join(isolatedCacheHome ?? "", "opencode-sandbox", "shim")

type ShellHook = (invocation: {
  command: string
  cwd: string
  timeout: number
  shell: string
  env: Record<string, string | undefined>
}) => Promise<void>

const makeEventBus = () => {
  const events: unknown[] = []
  let notify: (() => void) | undefined
  return {
    push(event: unknown) {
      events.push(event)
      notify?.()
    },
    subscribe: () =>
      ({
        [Symbol.asyncIterator]() {
          let index = 0
          return {
            async next() {
              while (index >= events.length)
                await new Promise<void>((resolve) => (notify = resolve))
              return { value: events[index++], done: false }
            },
            async return() {
              return { done: true, value: undefined }
            },
          }
        },
      }) as AsyncIterable<unknown>,
  }
}

const makeCtx = (directory = "/tmp/project") => {
  const hooks: Record<string, ShellHook> = {}
  const bus = makeEventBus()
  const ctx = {
    location: { directory },
    shell: {
      hook: (name: string, callback: ShellHook) => {
        hooks[name] = callback
        return Promise.resolve({ dispose: () => Promise.resolve() })
      },
    },
    event: { subscribe: () => bus.subscribe() },
  }
  return { ctx, hooks, bus }
}

const makeInvocation = (shell = "/bin/bash") => ({
  command: "echo hello",
  cwd: "/tmp/project",
  timeout: 0,
  shell,
  env: { TERM: "xterm-256color" },
})

const setupPlugin = async (directory?: string) => {
  const made = makeCtx(directory)
  const cleanup = await pluginModule.default.setup(made.ctx)
  return { ...made, cleanup }
}

describe("plugin", () => {
  let testConfigHome: string | undefined
  let isolatedConfigHome: string | undefined

  beforeAll(() => {
    testConfigHome = process.env.XDG_CONFIG_HOME
    isolatedConfigHome = fs.mkdtempSync(path.join(os.tmpdir(), "opencode-sandbox-test-config-"))
    process.env.XDG_CONFIG_HOME = isolatedConfigHome

    testCacheHome = process.env.XDG_CACHE_HOME
    isolatedCacheHome = fs.mkdtempSync(path.join(os.tmpdir(), "opencode-sandbox-test-cache-"))
    process.env.XDG_CACHE_HOME = isolatedCacheHome
  })

  afterAll(() => {
    if (isolatedConfigHome) fs.rmSync(isolatedConfigHome, { force: true, recursive: true })
    if (testConfigHome === undefined) delete process.env.XDG_CONFIG_HOME
    else process.env.XDG_CONFIG_HOME = testConfigHome

    if (isolatedCacheHome) fs.rmSync(isolatedCacheHome, { force: true, recursive: true })
    if (testCacheHome === undefined) delete process.env.XDG_CACHE_HOME
    else process.env.XDG_CACHE_HOME = testCacheHome
  })

  beforeEach(() => {
    mockInitialize.mockReset()
    mockInitialize.mockImplementation(() => Promise.resolve())
    mockWrapWithSandbox.mockReset()
    mockWrapWithSandbox.mockImplementation((cmd: string) => Promise.resolve(`srt-wrapped: ${cmd}`))
    mockCleanupAfterCommand.mockClear()
    mockRunEnforcementProbe.mockReset()
    mockRunEnforcementProbe.mockImplementation(() => Promise.resolve())
    mockBuildFenceCommand.mockReset()
    mockBuildFenceCommand.mockImplementation((_wrapped: string, _allowlist: string[]) =>
      Promise.resolve({ command: FENCE_TEST_COMMAND, dir: FENCE_TEST_DIR }),
    )
    mockFenceDependenciesMissing.mockReset()
    mockFenceDependenciesMissing.mockImplementation(() => [] as string[])
    mockSweepFenceDirs.mockReset()
    mockSweepFenceDirs.mockImplementation(() => Promise.resolve(0))
    mockRunFenceProbe.mockReset()
    mockRunFenceProbe.mockImplementation(() => Promise.resolve())
    fs.rmSync(FENCE_TEST_DIR, { recursive: true, force: true })
    delete process.env.OPENCODE_DISABLE_SANDBOX
    delete process.env.OPENCODE_SANDBOX_CONFIG
    delete process.env.OPENCODE_SANDBOX_CONFIG_PATH
  })

  test("exports the module shape: default { id, setup }", () => {
    expect(pluginModule.default.id).toBe("opencode-sandbox")
    expect(typeof pluginModule.default.setup).toBe("function")
  })

  test("root index.ts re-exports the plugin for local path loading", () => {
    expect(rootModule.default).toBe(pluginModule.default)
  })

  test("registers a shell create.before hook", async () => {
    const { hooks } = await setupPlugin()
    expect(hooks["create.before"]).toBeDefined()
  })

  test("registers no hooks when OPENCODE_DISABLE_SANDBOX=1", async () => {
    process.env.OPENCODE_DISABLE_SANDBOX = "1"
    const { hooks } = await setupPlugin()
    expect(hooks["create.before"]).toBeUndefined()
  })

  test("registers no hooks when config disables the plugin", async () => {
    process.env.OPENCODE_SANDBOX_CONFIG = JSON.stringify({ disabled: true })
    const { hooks } = await setupPlugin()
    expect(hooks["create.before"]).toBeUndefined()
  })

  const TEST_PROJECT = "/tmp/project"

  test("swaps the shell for a shim and leaves the command untouched", async () => {
    if (process.platform === "win32") return
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    // The command must stay raw: OpenCode's permission rules evaluate it.
    expect(invocation.command).toBe("echo hello")
    expect(mockInitialize).toHaveBeenCalledTimes(1)

    const shimPath = path.join(shimDir(), "sandbox", "bash")
    expect(invocation.shell).toBe(shimPath)
    expect(invocation.env.OPENCODE_SANDBOX_REAL_SHELL).toBe("/bin/bash")
    expect(invocation.env.OPENCODE_SANDBOX_WRAPPED_COMMAND).toBe("srt-wrapped: echo hello")
    // Pre-existing invocation env survives the merge
    expect(invocation.env.TERM).toBe("xterm-256color")

    const stat = fs.statSync(shimPath)
    expect(stat.mode & 0o111).not.toBe(0)
    const script = fs.readFileSync(shimPath, "utf8")
    expect(script).toContain("OPENCODE_SANDBOX_REAL_SHELL")
    expect(script).toContain("OPENCODE_SANDBOX_WRAPPED_COMMAND")
  })

  test("leaves the invocation untouched when the wrap is a no-op", async () => {
    if (process.platform === "win32") return
    mockWrapWithSandbox.mockImplementation((cmd: string) => Promise.resolve(cmd))
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation("/bin/zsh")

    await hooks["create.before"]?.(invocation)

    expect(invocation.shell).toBe("/bin/zsh")
    expect(invocation.env.OPENCODE_SANDBOX_WRAPPED_COMMAND).toBeUndefined()
    expect(fs.existsSync(path.join(shimDir(), "sandbox", "zsh"))).toBe(false)
  })

  test("wrap failure installs the blocked shim", async () => {
    if (process.platform === "win32") return
    mockWrapWithSandbox.mockImplementation(() => Promise.reject(new Error("boom")))
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    expect(invocation.command).toBe("echo hello")
    const blockedPath = path.join(shimDir(), "blocked", "bash")
    expect(invocation.shell).toBe(blockedPath)
    const script = fs.readFileSync(blockedPath, "utf8")
    expect(script).toContain("command blocked")
  })

  test("init failure installs the blocked shim", async () => {
    if (process.platform === "win32") return
    mockInitialize.mockImplementation(() => Promise.reject(new Error("no bwrap")))
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation("/bin/ksh")

    await hooks["create.before"]?.(invocation)

    expect(invocation.shell).toBe(path.join(shimDir(), "blocked", "ksh"))
  })

  test("probe runs exactly once before the first command", async () => {
    if (process.platform === "win32") return
    const { hooks } = await setupPlugin()
    await hooks["create.before"]?.(makeInvocation("/bin/zsh"))
    await hooks["create.before"]?.(makeInvocation("/bin/bash"))

    expect(mockRunEnforcementProbe).toHaveBeenCalledTimes(1)
  })

  test("probe failure installs the blocked shim", async () => {
    if (process.platform === "win32") return
    mockRunEnforcementProbe.mockImplementation(() =>
      Promise.reject(new Error("the sandbox did not block a forbidden write")),
    )
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    expect(invocation.shell).toBe(path.join(shimDir(), "blocked", "bash"))
  })

  test("invalid config blocks commands with the reason in the shim", async () => {
    process.env.OPENCODE_SANDBOX_CONFIG = "broken{json"
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    expect(invocation.shell).toContain(path.join(shimDir(), "blocked"))
    const script = fs.readFileSync(invocation.shell, "utf8")
    expect(script).toContain("invalid sandbox config")
    expect(script).toContain("Invalid JSON in OPENCODE_SANDBOX_CONFIG")
  })

  test("invalid config respects the toggle", async () => {
    process.env.OPENCODE_SANDBOX_CONFIG = "broken{json"
    await toggleModule.setSandboxToggledOff(TEST_PROJECT, true)
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    expect(invocation.shell).toBe("/bin/bash")
    await toggleModule.setSandboxToggledOff(TEST_PROJECT, false)
  })

  test("skips sandboxing when toggled off", async () => {
    if (process.platform === "win32") return
    await toggleModule.setSandboxToggledOff(TEST_PROJECT, true)
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    expect(invocation.shell).toBe("/bin/bash")
    expect(invocation.env.OPENCODE_SANDBOX_WRAPPED_COMMAND).toBeUndefined()
    expect(mockInitialize).not.toHaveBeenCalled()

    await toggleModule.setSandboxToggledOff(TEST_PROJECT, false)
  })

  test("resumes sandboxing when toggled back on", async () => {
    if (process.platform === "win32") return
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    expect(invocation.shell).toBe(path.join(shimDir(), "sandbox", "bash"))
    expect(invocation.env.OPENCODE_SANDBOX_WRAPPED_COMMAND).toBe("srt-wrapped: echo hello")
  })

  test("resolves relative globs against invocation cwd", async () => {
    if (process.platform === "win32") return
    process.env.OPENCODE_SANDBOX_CONFIG = JSON.stringify({
      filesystem: {
        denyRead: [".envrc"],
      },
    })
    const { hooks } = await setupPlugin("/tmp/project")
    const invocation = makeInvocation()
    invocation.cwd = "/tmp/other-dir"

    await hooks["create.before"]?.(invocation)

    expect(mockWrapWithSandbox).toHaveBeenCalledTimes(1)
    const customConfig = mockWrapWithSandbox.mock.calls[0][2]
    expect(customConfig).toBeDefined()
    expect(customConfig.filesystem).toBeDefined()
    expect(customConfig.filesystem.denyRead).toContain("/tmp/other-dir/.envrc")
    expect(customConfig.filesystem.denyRead).not.toContain("/tmp/project/.envrc")
  })

  test("fenced wraps the sandboxed command in the pasta fence", async () => {
    if (process.platform !== "linux") return
    process.env.OPENCODE_SANDBOX_CONFIG = JSON.stringify({
      network: { fenced: true, allowedDomains: ["pypi.org"] },
    })
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    // The fence receives the runtime's (network-less) wrap and the user's
    // allowlist, and its command replaces the wrap in the shim.
    expect(mockBuildFenceCommand).toHaveBeenCalledTimes(1)
    expect(mockBuildFenceCommand.mock.calls[0][0]).toBe("srt-wrapped: echo hello")
    expect(mockBuildFenceCommand.mock.calls[0][1]).toEqual(["pypi.org"])
    expect(mockRunFenceProbe).toHaveBeenCalledTimes(1)
    expect(invocation.command).toBe("echo hello")
    expect(invocation.shell).toBe(path.join(shimDir(), "sandbox", "bash"))
    expect(invocation.env.OPENCODE_SANDBOX_WRAPPED_COMMAND).toBe(FENCE_TEST_COMMAND)
  })

  test("fenced uses the default allowlist when none is configured", async () => {
    if (process.platform !== "linux") return
    process.env.OPENCODE_SANDBOX_CONFIG = JSON.stringify({ network: { fenced: true } })
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    const allowlist = mockBuildFenceCommand.mock.calls[0][1]
    expect(allowlist).toContain("registry.npmjs.org")
    expect(allowlist).toContain("github.com")
  })

  test("fenced blocks commands when a dependency is missing", async () => {
    if (process.platform !== "linux") return
    mockFenceDependenciesMissing.mockImplementation(() => ["pasta"])
    process.env.OPENCODE_SANDBOX_CONFIG = JSON.stringify({ network: { fenced: true } })
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    expect(invocation.shell).toContain(path.join(shimDir(), "blocked"))
    expect(fs.readFileSync(invocation.shell, "utf8")).toContain("pasta")
    expect(mockBuildFenceCommand).not.toHaveBeenCalled()
  })

  test("fenced releases the runtime's command count when the fence cannot be built", async () => {
    if (process.platform !== "linux") return
    mockBuildFenceCommand.mockImplementation(() => Promise.reject(new Error("ENOSPC")))
    process.env.OPENCODE_SANDBOX_CONFIG = JSON.stringify({ network: { fenced: true } })
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    // Blocked, and the wrap's refcount released right away: no sandbox shim
    // was handed out, so no "ended" event would ever release it.
    expect(invocation.shell).toContain(path.join(shimDir(), "blocked"))
    expect(mockCleanupAfterCommand).toHaveBeenCalledTimes(1)
  })

  test("fenced blocks commands when the fence probe fails", async () => {
    if (process.platform !== "linux") return
    mockRunFenceProbe.mockImplementation(() => Promise.reject(new Error("no userns")))
    process.env.OPENCODE_SANDBOX_CONFIG = JSON.stringify({ network: { fenced: true } })
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    expect(invocation.shell).toContain(path.join(shimDir(), "blocked"))
    expect(mockBuildFenceCommand).not.toHaveBeenCalled()
  })

  test("fenced passes deniedDomains and reports each skip warning once", async () => {
    if (process.platform !== "linux") return
    mockBuildFenceCommand.mockImplementation((_w, _a, options) => {
      options?.warn?.("fence: ignoring allowlist entry *.x.org")
      return Promise.resolve({ command: FENCE_TEST_COMMAND, dir: FENCE_TEST_DIR })
    })
    process.env.OPENCODE_SANDBOX_CONFIG = JSON.stringify({
      network: { fenced: true, allowedDomains: ["*.x.org"], deniedDomains: ["evil.org"] },
    })
    const warn = console.warn
    const warnings: string[] = []
    console.warn = (m: string) => warnings.push(m)
    try {
      const { hooks } = await setupPlugin()
      await hooks["create.before"]?.(makeInvocation())
      await hooks["create.before"]?.(makeInvocation())
    } finally {
      console.warn = warn
    }
    expect(mockBuildFenceCommand.mock.calls[0][2]?.denylist).toEqual(["evil.org"])
    expect(warnings.filter((m) => m.includes("*.x.org"))).toHaveLength(1)
  })

  test("fenced respects the toggle", async () => {
    if (process.platform !== "linux") return
    process.env.OPENCODE_SANDBOX_CONFIG = JSON.stringify({ network: { fenced: true } })
    await toggleModule.setSandboxToggledOff(TEST_PROJECT, true)
    const { hooks } = await setupPlugin()
    const invocation = makeInvocation()

    await hooks["create.before"]?.(invocation)

    expect(invocation.shell).toBe("/bin/bash")
    expect(mockBuildFenceCommand).not.toHaveBeenCalled()
    await toggleModule.setSandboxToggledOff(TEST_PROJECT, false)
  })

  test("fenced removes the fence dir on session.shell.ended", async () => {
    if (process.platform !== "linux") return
    process.env.OPENCODE_SANDBOX_CONFIG = JSON.stringify({
      network: { fenced: true, allowedDomains: ["pypi.org"] },
    })
    const { hooks, bus } = await setupPlugin()
    const invocation = makeInvocation()
    await hooks["create.before"]?.(invocation)
    fs.mkdirSync(FENCE_TEST_DIR, { recursive: true })

    // An ended shell for a different command must not touch the dir.
    bus.push({
      type: "session.shell.ended",
      data: { sessionID: "s1", shell: { shell: invocation.shell, command: "other command" } },
    })
    await new Promise((resolve) => setTimeout(resolve, 5))
    expect(fs.existsSync(FENCE_TEST_DIR)).toBe(true)

    bus.push({
      type: "session.shell.ended",
      data: { sessionID: "s1", shell: { shell: invocation.shell, command: invocation.command } },
    })
    await new Promise((resolve) => setTimeout(resolve, 10))
    expect(fs.existsSync(FENCE_TEST_DIR)).toBe(false)
  })

  test("fenced removes only the oldest dir of identical concurrent commands", async () => {
    if (process.platform !== "linux") return
    const first = `${FENCE_TEST_DIR}-1`
    const second = `${FENCE_TEST_DIR}-2`
    const dirs = [first, second]
    mockBuildFenceCommand.mockImplementation(() =>
      Promise.resolve({ command: FENCE_TEST_COMMAND, dir: dirs.shift() as string }),
    )
    process.env.OPENCODE_SANDBOX_CONFIG = JSON.stringify({ network: { fenced: true } })
    const { hooks, bus } = await setupPlugin()
    const a = makeInvocation()
    const b = makeInvocation()
    await hooks["create.before"]?.(a)
    await hooks["create.before"]?.(b)
    for (const d of [first, second]) fs.mkdirSync(d, { recursive: true })

    const ended = { sessionID: "s1", shell: { shell: a.shell, command: a.command } }
    bus.push({ type: "session.shell.ended", data: ended })
    await new Promise((resolve) => setTimeout(resolve, 10))
    expect(fs.existsSync(first)).toBe(false)
    expect(fs.existsSync(second)).toBe(true)

    bus.push({ type: "session.shell.ended", data: ended })
    await new Promise((resolve) => setTimeout(resolve, 10))
    expect(fs.existsSync(second)).toBe(false)
  })

  test("cleans up once per sandboxed shell on session.shell.ended", async () => {
    if (process.platform === "win32") return
    const { hooks, bus } = await setupPlugin()
    const invocation = makeInvocation()
    await hooks["create.before"]?.(invocation)
    const shimPath = invocation.shell

    // A shell that is not ours must not trigger cleanup
    bus.push({
      type: "session.shell.ended",
      data: { sessionID: "s1", shell: { shell: "/bin/bash" } },
    })
    await new Promise((resolve) => setTimeout(resolve, 5))
    expect(mockCleanupAfterCommand).not.toHaveBeenCalled()

    bus.push({ type: "session.shell.ended", data: { sessionID: "s1", shell: { shell: shimPath } } })
    bus.push({ type: "session.shell.ended", data: { sessionID: "s1", shell: { shell: shimPath } } })
    await new Promise((resolve) => setTimeout(resolve, 5))
    expect(mockCleanupAfterCommand).toHaveBeenCalledTimes(2)
  })

  test("ignores unrelated event types", async () => {
    if (process.platform === "win32") return
    const { hooks, bus } = await setupPlugin()
    const invocation = makeInvocation()
    await hooks["create.before"]?.(invocation)

    bus.push({ type: "session.idle", data: { sessionID: "s1" } })
    await new Promise((resolve) => setTimeout(resolve, 5))
    expect(mockCleanupAfterCommand).not.toHaveBeenCalled()
  })

  test("cleanup stops the event loop", async () => {
    if (process.platform === "win32") return
    const { hooks, bus, cleanup } = await setupPlugin()
    const invocation = makeInvocation()
    await hooks["create.before"]?.(invocation)

    expect(typeof cleanup).toBe("function")
    await cleanup?.()

    bus.push({
      type: "session.shell.ended",
      data: { sessionID: "s1", shell: { shell: invocation.shell } },
    })
    await new Promise((resolve) => setTimeout(resolve, 5))
    expect(mockCleanupAfterCommand).not.toHaveBeenCalled()
  })
})
