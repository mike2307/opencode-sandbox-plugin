import fs from "node:fs"
import fsPromises from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import type { SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime"

export interface SandboxPluginConfig {
  disabled?: boolean
  filesystem?: {
    denyRead?: string[]
    allowRead?: string[]
    allowWrite?: string[]
    denyWrite?: string[]
  }
  network?: {
    disabled?: boolean
    fenced?: boolean
    allowedDomains?: string[]
    deniedDomains?: string[]
    allowUnixSockets?: string[]
    allowAllUnixSockets?: boolean
    allowLocalBinding?: boolean
  }
}

const DEFAULT_DENY_READ_DIRS = [
  ".ssh",
  ".gnupg",
  ".aws/credentials",
  ".azure",
  ".config/gcloud",
  ".config/gh",
  ".kube",
  ".docker/config.json",
  ".npmrc",
  ".netrc",
  ".env",
]

export const DEFAULT_ALLOWED_DOMAINS = [
  "registry.npmjs.org",
  "*.npmjs.org",
  "registry.yarnpkg.com",
  "pypi.org",
  "*.pypi.org",
  "crates.io",
  "*.crates.io",
  "github.com",
  "*.github.com",
  "gitlab.com",
  "*.gitlab.com",
  "bitbucket.org",
  "*.bitbucket.org",
  "api.openai.com",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
  "*.googleapis.com",
]

const UNSAFE_WRITE_PATHS = new Set([
  "/",
  "/home",
  "/usr",
  "/etc",
  "/var",
  "/opt",
  "/Library",
  "/System",
  "/private",
  "/Volumes",
  "/Users",
])

function isSafeWritePath(p: string): boolean {
  const normalized = path.resolve(p)
  if (UNSAFE_WRITE_PATHS.has(normalized)) {
    console.warn(`[opencode-sandbox] Rejecting unsafe write path: ${normalized}`)
    return false
  }
  return true
}

/** Resolve a user-supplied path relative to projectDir if it is not
 * absolute and does not start with ~ (which the runtime expands). */
function resolveUserPath(p: string, projectDir: string): string {
  if (p.startsWith("/") || p.startsWith("~")) return p
  return path.resolve(projectDir, p)
}

export function resolveConfig(
  projectDir: string,
  worktree: string,
  user?: SandboxPluginConfig,
): SandboxRuntimeConfig {
  // macOS resolves symlinks before applying sandbox filters, so relative
  // globs and projectDir-anchored rules must be built from the canonical
  // path or the profile will not match.
  let canonicalProjectDir: string
  try {
    canonicalProjectDir = fs.realpathSync(projectDir)
  } catch {
    canonicalProjectDir = path.resolve(projectDir)
  }

  const homeDir = os.homedir()

  const candidatePaths = [projectDir, worktree, os.tmpdir()].filter(Boolean)
  const safePaths = candidatePaths.filter((p) => isSafeWritePath(p))
  const writePaths = user?.filesystem?.allowWrite
    ? user.filesystem.allowWrite.map((p) => resolveUserPath(p, canonicalProjectDir))
    : [...new Set(safePaths.map((p) => path.resolve(p)))]

  const userDenyRead = user?.filesystem?.denyRead
  const userAllowRead = user?.filesystem?.allowRead
  const userDenyWrite = user?.filesystem?.denyWrite

  return {
    filesystem: {
      denyRead: userDenyRead
        ? userDenyRead.map((p) => resolveUserPath(p, canonicalProjectDir))
        : DEFAULT_DENY_READ_DIRS.map((p) => path.join(homeDir, p)),
      allowRead: userAllowRead
        ? userAllowRead.map((p) => resolveUserPath(p, canonicalProjectDir))
        : [],
      allowWrite: writePaths,
      denyWrite: userDenyWrite
        ? userDenyWrite.map((p) => resolveUserPath(p, canonicalProjectDir))
        : [],
    },
    network:
      user?.network?.disabled || user?.network?.fenced
        ? // Disabled OR fenced: omit allowedDomains so the runtime sets
          // needsNetworkRestriction to false — no --unshare-net namespace, no
          // proxy env injection, host network used directly by bwrap. For
          // fenced, the plugin separately owns the network via a pasta sidecar
          // (src/fence.ts); the runtime must not touch the network. The public
          // type marks the field required, but every runtime read goes through
          // `?.` / `?? []`, so its absence is safe.
          ({ deniedDomains: [] } as unknown as SandboxRuntimeConfig["network"])
        : {
            allowedDomains: user?.network?.allowedDomains ?? DEFAULT_ALLOWED_DOMAINS,
            deniedDomains: user?.network?.deniedDomains ?? [],
            allowUnixSockets: user?.network?.allowUnixSockets,
            allowAllUnixSockets: user?.network?.allowAllUnixSockets,
            allowLocalBinding: user?.network?.allowLocalBinding ?? false,
          },
  }
}

const FILESYSTEM_KEYS = new Set(["denyRead", "allowRead", "allowWrite", "denyWrite"])
const NETWORK_KEYS = new Set([
  "disabled",
  "fenced",
  "allowedDomains",
  "deniedDomains",
  "allowUnixSockets",
  "allowAllUnixSockets",
  "allowLocalBinding",
])

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((entry) => typeof entry === "string")

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value)

const messageOf = (err: unknown) => (err instanceof Error ? err.message : String(err))

/** Structural validation of a loaded config.
 *
 * `errors` are conditions the plugin cannot interpret safely — the caller must
 * block commands rather than fall through to weaker defaults. `warnings` cover
 * unknown keys, which may be written for a newer plugin version and are
 * ignored without blocking. */
export function validateConfig(config: unknown): { errors: string[]; warnings: string[] } {
  const errors: string[] = []
  const warnings: string[] = []
  if (!isObject(config)) return { errors: ["config must be a JSON object"], warnings }

  for (const [key, value] of Object.entries(config)) {
    if (key === "disabled") {
      if (typeof value !== "boolean") errors.push("disabled must be a boolean")
    } else if (key === "filesystem" || key === "network") {
      const knownKeys = key === "filesystem" ? FILESYSTEM_KEYS : NETWORK_KEYS
      if (!isObject(value)) {
        errors.push(`${key} must be a JSON object`)
        continue
      }
      for (const [subKey, subValue] of Object.entries(value)) {
        if (!knownKeys.has(subKey)) {
          warnings.push(`ignoring unknown key "${key}.${subKey}"`)
        } else if (
          subKey === "allowAllUnixSockets" ||
          subKey === "allowLocalBinding" ||
          subKey === "disabled" ||
          subKey === "fenced"
        ) {
          if (typeof subValue !== "boolean") errors.push(`${key}.${subKey} must be a boolean`)
        } else if (!isStringArray(subValue)) {
          errors.push(`${key}.${subKey} must be an array of strings`)
        }
      }
    } else {
      warnings.push(`ignoring unknown key "${key}"`)
    }
  }
  const network = isObject(config.network) ? config.network : undefined
  if (network?.fenced === true) {
    // Ambiguous: unrestricted network vs. the fence. Fail closed.
    if (network.disabled === true)
      errors.push("network.disabled and network.fenced are mutually exclusive")
    for (const subKey of FENCE_IGNORED_KEYS)
      if (subKey in network) warnings.push(`network.${subKey} has no effect with network.fenced`)
  }
  return { errors, warnings }
}

/** Proxy-model network keys the fence does not use (Unix sockets stay blocked
 * by the runtime's seccomp filter; local binding is always possible inside
 * the fence's own network namespace). */
const FENCE_IGNORED_KEYS = ["allowUnixSockets", "allowAllUnixSockets", "allowLocalBinding"]

/** Apply validation to a parsed config, throwing on structural errors so the
 * caller fails closed instead of silently weakening to defaults. */
function checkedConfig(source: string, config: unknown): SandboxPluginConfig {
  const { errors, warnings } = validateConfig(config)
  for (const warning of warnings) console.warn(`[opencode-sandbox] ${source}: ${warning}`)
  if (errors.length > 0) throw new Error(`Invalid config (${source}): ${errors.join("; ")}`)
  return config as SandboxPluginConfig
}

export function isSandboxGloballyDisabled(): boolean {
  return (
    process.env.OPENCODE_DISABLE_SANDBOX === "1" || process.env.OPENCODE_DISABLE_SANDBOX === "true"
  )
}

/** Read and parse a config file. Missing files (ENOENT) return null so the
 * search continues; a file that exists but cannot be read or parsed throws so
 * the caller fails closed rather than skipping a restriction the user set. */
async function readJsonConfig(filePath: string): Promise<unknown> {
  let content: string
  try {
    content = await fsPromises.readFile(filePath, "utf-8")
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null
    throw new Error(`Cannot read config file ${filePath}: ${messageOf(err)}`)
  }
  try {
    return JSON.parse(content)
  } catch (err) {
    throw new Error(`Invalid JSON in config file ${filePath}: ${messageOf(err)}`)
  }
}

export async function loadConfig(projectDir: string): Promise<SandboxPluginConfig> {
  const envConfig = process.env.OPENCODE_SANDBOX_CONFIG
  if (envConfig) {
    let parsed: unknown
    try {
      parsed = JSON.parse(envConfig)
    } catch (err) {
      throw new Error(`Invalid JSON in OPENCODE_SANDBOX_CONFIG: ${messageOf(err)}`)
    }
    return checkedConfig("OPENCODE_SANDBOX_CONFIG", parsed)
  }

  const envConfigPath = process.env.OPENCODE_SANDBOX_CONFIG_PATH
  if (envConfigPath) {
    const customConfig = await readJsonConfig(envConfigPath)
    if (customConfig !== null) {
      return checkedConfig(`OPENCODE_SANDBOX_CONFIG_PATH (${envConfigPath})`, customConfig)
    }
    console.warn(
      `[opencode-sandbox] Failed to load config from OPENCODE_SANDBOX_CONFIG_PATH: ${envConfigPath}`,
    )
  }

  const configBase = process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config")
  const legacyDir = path.join(configBase, "opencode-sandbox")
  const standardDir = path.join(configBase, "opencode")
  const projectName = path.basename(projectDir)

  const sources = [
    path.join(standardDir, "projects", `${projectName}.sandbox.json`),
    path.join(legacyDir, "projects", `${projectName}.json`),
    path.join(standardDir, "sandbox.json"),
    path.join(legacyDir, "config.json"),
  ]

  for (const source of sources) {
    const config = await readJsonConfig(source)
    if (config !== null) return checkedConfig(source, config)
  }

  return {}
}
