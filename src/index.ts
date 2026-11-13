import fsPromises from "node:fs/promises"
import { SandboxManager } from "@anthropic-ai/sandbox-runtime"
import { Plugin } from "@opencode/plugin"
import {
  DEFAULT_ALLOWED_DOMAINS,
  isSandboxGloballyDisabled,
  loadConfig,
  resolveConfig,
  type SandboxPluginConfig,
} from "./config"
import { buildFenceCommand, fenceDependenciesMissing, sweepFenceDirs } from "./fence"
import { runEnforcementProbe } from "./probe"
import { ENFORCEMENT_MESSAGE, ensureShim } from "./shim"
import { cleanupOldToggleFiles, isSandboxToggledOff } from "./toggle"

export type { SandboxPluginConfig } from "./config"

const log = (level: "warn" | "error", message: string) =>
  console[level](`[opencode-sandbox] ${message}`)
const messageOf = (err: unknown) => (err instanceof Error ? err.message : String(err))

// Sandboxes by swapping the shell binary for a shim (src/shim.ts) and leaving
// invocation.command untouched: OpenCode's permission rules, shell scanning and
// directory authorization all evaluate the raw command, while the sandbox still
// applies to every process the shell spawns.
export default Plugin.define({
  id: "opencode-sandbox",
  async setup(ctx) {
    if (isSandboxGloballyDisabled()) {
      return
    }

    const projectDir = ctx.location.directory

    let userConfig: SandboxPluginConfig
    try {
      userConfig = await loadConfig(projectDir)
    } catch (err) {
      // A config file that was found but cannot be used must not fall through
      // to weaker defaults — block commands instead, with the shim naming the
      // problem so the failure is visible to the agent, not only the log.
      const message = messageOf(err)
      log(
        "error",
        `${message}; commands will be blocked until the config is fixed or the sandbox is toggled off`,
      )
      const registration = await ctx.shell.hook("create.before", async (invocation) => {
        if (await isSandboxToggledOff(projectDir)) return
        invocation.shell = await ensureShim(
          invocation.shell,
          "blocked",
          `opencode-sandbox: command blocked — invalid sandbox config: ${message}`,
        )
      })
      return () => {
        void registration.dispose()
      }
    }

    if (userConfig.disabled) return

    await cleanupOldToggleFiles()

    if (process.platform === "win32") {
      log("error", "Windows sandboxing is not available; commands will be blocked")
      const registration = await ctx.shell.hook("create.before", async (invocation) => {
        if (await isSandboxToggledOff(projectDir)) return
        invocation.shell = await ensureShim(invocation.shell, "blocked")
      })
      return () => {
        void registration.dispose()
      }
    }

    const fenced = userConfig.network?.fenced === true
    if (fenced && process.platform !== "linux") {
      log("error", "network.fenced requires Linux (pasta + nftables); commands will be blocked")
      const registration = await ctx.shell.hook("create.before", async (invocation) => {
        if (await isSandboxToggledOff(projectDir)) return
        invocation.shell = await ensureShim(
          invocation.shell,
          "blocked",
          "opencode-sandbox: network.fenced requires Linux — command blocked",
        )
      })
      return () => {
        void registration.dispose()
      }
    }
    if (fenced) {
      const missing = fenceDependenciesMissing()
      if (missing.length > 0) {
        log(
          "error",
          `network.fenced is enabled but ${missing.join(", ")} is missing (or not in PATH); commands will be blocked`,
        )
        const registration = await ctx.shell.hook("create.before", async (invocation) => {
          if (await isSandboxToggledOff(projectDir)) return
          invocation.shell = await ensureShim(
            invocation.shell,
            "blocked",
            `opencode-sandbox: network.fenced requires ${missing.join(", ")} — command blocked`,
          )
        })
        return () => {
          void registration.dispose()
        }
      }
      // Scratch dirs left behind by commands that were killed before the guest
      // could remove its own dir.
      void sweepFenceDirs().then((removed) => {
        if (removed > 0) console.debug(`[opencode-sandbox] swept ${removed} stale fence dir(s)`)
      })
    }

    const runtimeConfig = resolveConfig(projectDir, projectDir, userConfig)

    let initialization: Promise<boolean> | undefined
    const ensureSandboxReady = () =>
      (initialization ??= SandboxManager.initialize(runtimeConfig)
        // Initialization only proves the runtime configured itself; the probe
        // proves seatbelt/bwrap actually enforce before the first real command.
        .then(() => runEnforcementProbe())
        .then(() => {
          console.debug(
            `[opencode-sandbox] initialized and enforcement verified — writes allowed in: ${runtimeConfig.filesystem?.allowWrite?.join(", ")}`,
          )
          return true
        })
        .catch((err) => {
          log(
            "error",
            `Failed to initialize or verify the sandbox; commands will be blocked: ${messageOf(err)}`,
          )
          return false
        }))

    // Sandbox shims currently handed out; shell "ended" events carrying one of
    // these paths belong to commands this instance wrapped and must release the
    // runtime's per-command mount-point refcount.
    const sandboxShimPaths = new Set<string>()

    // Fence scratch dirs by original command string; a "session.shell.ended"
    // event carries the command, which lets the dir be removed even when the
    // guest could not (a killed command). If an identical command is still
    // running, its dir may be removed early — harmless, its files are all
    // consumed before the user command starts.
    const fenceDirsByCommand = new Map<string, Set<string>>()

    const cleanupCommand = () => {
      try {
        SandboxManager.cleanupAfterCommand()
      } catch (err) {
        log("warn", `Failed to clean up sandbox mount points: ${messageOf(err)}`)
      }
    }

    const shellRegistration = await ctx.shell.hook("create.before", async (invocation) => {
      if (await isSandboxToggledOff(projectDir)) return
      if (!invocation.command) return

      try {
        if (!(await ensureSandboxReady())) throw new Error("sandbox initialization failed")

        // Resolve relative path globs against the shell's current working
        // directory so sandbox rules track where commands actually run.
        const invocationConfig = resolveConfig(invocation.cwd, invocation.cwd, userConfig)

        let wrapped = await SandboxManager.wrapWithSandbox(
          invocation.command,
          invocation.shell,
          { filesystem: invocationConfig.filesystem },
          undefined,
          { commandId: crypto.randomUUID(), commandText: invocation.command },
        )

        // network.fenced: the runtime above ran with networking disabled (no
        // --unshare-net, no proxy), so this bwrap command is a pure filesystem
        // sandbox. Wrap it in the per-command pasta fence, which owns the
        // network namespace (pinned resolver + egress allowlist); the bwrap
        // command inherits that netns and the bind-mounted resolver overrides.
        if (fenced) {
          const fence = await buildFenceCommand(
            wrapped,
            userConfig.network?.allowedDomains ?? DEFAULT_ALLOWED_DOMAINS,
            { warn: (message) => log("warn", message) },
          )
          let fenceDirs = fenceDirsByCommand.get(invocation.command)
          if (!fenceDirs) {
            fenceDirs = new Set()
            fenceDirsByCommand.set(invocation.command, fenceDirs)
          }
          fenceDirs.add(fence.dir)
          wrapped = fence.command
        }
        // No restrictions apply to this command; skip the shim entirely.
        if (wrapped === invocation.command) return

        const shimPath = await ensureShim(invocation.shell, "sandbox")
        sandboxShimPaths.add(shimPath)
        invocation.env = {
          ...invocation.env,
          OPENCODE_SANDBOX_REAL_SHELL: invocation.shell,
          OPENCODE_SANDBOX_WRAPPED_COMMAND: wrapped,
        }
        invocation.shell = shimPath
      } catch (err) {
        log("error", `Failed to sandbox command; blocking it: ${messageOf(err)}`)
        try {
          invocation.shell = await ensureShim(invocation.shell, "blocked")
        } catch {
          // Fail closed even when the blocked shim cannot be written.
          invocation.command = `echo '${ENFORCEMENT_MESSAGE}' >&2; exit 126`
        }
      }
    })

    // cleanupAfterCommand() must run exactly once per wrapped command, in this
    // process (the runtime's mount-point refcount lives here). The shell "ended"
    // event fires for every Shell.create exit path — completion, failure,
    // timeout, interrupt.
    let disposed = false
    let stopped: (() => void) | undefined
    const stoppedPromise = new Promise<void>((resolve) => (stopped = resolve))
    const iterator = ctx.event.subscribe()[Symbol.asyncIterator]()
    type Next = Awaited<ReturnType<typeof iterator.next>>
    void (async () => {
      try {
        while (!disposed) {
          // Race the next event against teardown: a parked next() would keep the
          // subscription (and the host process) alive long after dispose.
          const stop: Next = { done: true, value: undefined as never }
          const result = await Promise.race([iterator.next(), stoppedPromise.then(() => stop)])
          if (result.done) break
          if (result.value.type !== "session.shell.ended") continue
          const shell = result.value.data.shell
          if (sandboxShimPaths.has(shell.shell)) cleanupCommand()
          const fenceDirs = fenceDirsByCommand.get(shell.command)
          if (fenceDirs) {
            fenceDirsByCommand.delete(shell.command)
            for (const fenceDir of fenceDirs) {
              fsPromises
                .rm(fenceDir, { recursive: true, force: true })
                .catch((err) =>
                  log("warn", `Failed to remove fence dir ${fenceDir}: ${messageOf(err)}`),
                )
            }
          }
        }
      } catch {
        // Stream closed (server shutdown or plugin teardown); nothing to clean.
      }
    })()

    return () => {
      disposed = true
      stopped?.()
      void iterator.return?.()
      void shellRegistration.dispose()
    }
  },
})
