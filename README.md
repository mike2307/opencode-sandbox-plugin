[![CI](https://github.com/isanchez31/opencode-sandbox-plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/isanchez31/opencode-sandbox-plugin/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/opencode-sandbox)](https://www.npmjs.com/package/opencode-sandbox)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# opencode-sandbox

An [OpenCode](https://opencode.ai) plugin that sandboxes agent-executed commands using [`@anthropic-ai/sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime).

Every command the agent runs through OpenCode is wrapped with OS-level filesystem and network restrictions — no containers, no VMs, just native OS sandboxing primitives.

| Platform | Mechanism |
|----------|-----------|
| **macOS** | `sandbox-exec` (Seatbelt profiles) |
| **Linux** | `bubblewrap` (namespace isolation) |
| **Windows** | Not yet supported (commands are blocked) |

## Install

Requires OpenCode 2 or later.

```json
// opencode.json
{
  "plugins": ["opencode-sandbox"]
}
```

The plugin is automatically installed from npm when OpenCode starts.

To use a local checkout instead of the npm package, point `plugins` at the repository directory — the local entry loads `index.ts` and `tui.ts` from source, no build needed:

```json
{
  "plugins": ["/path/to/opencode-sandbox-plugin"]
}
```

Verify with `opencode plugin list`.

### Linux prerequisites

**1. Install bubblewrap and socat:**

```bash
# Debian/Ubuntu
sudo apt install bubblewrap socat

# Fedora
sudo dnf install bubblewrap socat

# Arch
sudo pacman -S bubblewrap socat
```

Both are required on every Linux machine, in every sandbox mode: `@anthropic-ai/sandbox-runtime` checks `socat` at initialization (it operates the proxy-based network sandbox's network bridge) and blocks all commands with `Sandbox dependencies not available: socat not installed` when it is missing — even when you only use the network fence, which does not use socat itself.

**2. Ubuntu 24.04+ (AppArmor fix):**

Ubuntu 24.04 and later restrict unprivileged user namespaces via AppArmor, which prevents bubblewrap from working. You need to enable the `bwrap-userns-restrict` AppArmor profile:

```bash
# Install the AppArmor profiles package
sudo apt install apparmor-profiles

# Create the symlink to enable the profile
sudo ln -s /etc/apparmor.d/bwrap-userns-restrict /etc/apparmor.d/force-complain/bwrap-userns-restrict

# Load the profile
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
```

You can verify bwrap works:

```bash
bwrap --ro-bind / / --dev /dev --proc /proc -- echo "sandbox works"
```

Without this fix, bwrap will fail with `loopback: Failed RTM_NEWADDR: Operation not permitted` or `setting up uid map: Permission denied`.

**3. (Only for the network fence)** If you use `network.fenced: true`, the fence needs a few more tools on the host, in addition to bubblewrap and socat:

```bash
# Debian/Ubuntu
sudo apt install passt util-linux python3 nftables iproute2

# Fedora
sudo dnf install passt util-linux python3 nftables iproute

# Arch
sudo pacman -S passt util-linux python nftables iproute2
```

The fence shells out to `pasta` and `unshare`/`mount` (util-linux), `/usr/bin/python3` (the DNS responder), `nft` (nftables), and `ip` (iproute2). If any are missing, commands are blocked with the missing tool named.

## What it does

When the agent runs a command, the sandbox enforces three layers of protection:

### Filesystem write protection

Commands can only write to the project directory and `/tmp`. Writing anywhere else returns "Read-only file system":

```
$ touch ~/some-file
touch: cannot touch '/home/user/some-file': Read-only file system

$ echo "data" > /etc/config
/usr/bin/bash: line 1: /etc/config: Read-only file system
```

### Sensitive file read protection

Access to credential directories is blocked:

```
$ cat ~/.ssh/id_rsa
cat: /home/user/.ssh/id_rsa: Permission denied
```

### Network allowlist

Only approved domains are reachable. All other traffic is blocked via a local proxy:

```
$ curl https://evil.com
Connection blocked by network allowlist

$ curl https://registry.npmjs.org
(works — npmjs.org is in the default allowlist)
```

### Disable the network sandbox

Set `network.disabled: true` to run commands with **unrestricted network access** while keeping all filesystem (read/write) restrictions in place. The local allow-list proxy is not started at all — no `HTTP(S)_PROXY`/`NO_PROXY` is injected and no isolated network namespace is created, so commands reach the host network directly:

```json
{
  "network": {
    "disabled": true
  }
}
```

`disabled` takes precedence over `allowedDomains`/`deniedDomains` in the same block (they are ignored). Filesystem sandboxing is unaffected; the whole-sandbox switches (top-level `disabled: true`, `OPENCODE_DISABLE_SANDBOX=1`, and "Toggle Sandbox") still disable *everything*, network included.

### Network fence (proxy-less egress allowlist, Linux)

`network.fenced: true` replaces the proxy-based network sandbox with a **per-command network fence** built on `pasta` — no `HTTP(S)_PROXY` injection, no proxy process, no app-level hooks. Filesystem sandboxing (bubblewrap) stays fully in place and nests inside the fence:

```json
{
  "network": {
    "fenced": true,
    "allowedDomains": [
      "registry.npmjs.org",
      "pypi.org",
      "github.com",
      "10.16.59.0/24",
      "10.17.146.234"
    ]
  }
}
```

How it works: each command runs inside a `pasta` network namespace that the plugin creates for it and tears down afterwards. Three cooperating, unprivileged layers gate egress:

1. **Name gate** — a minimal in-namespace DNS responder answers *only* what the allowlist permits: pinned domain names with the addresses the plugin resolved on the host for this command, and — for `*.domain` entries — strict subdomains vouched on demand by a host-side resolver that runs alongside the fence (and opens the egress ruleset for the addresses it answers). Every other name gets NXDOMAIN. Commands can only ever *learn* allowed destinations.
2. **IP backstop** — an nftables policy-drop ruleset (`inet`, so IPv6 is dropped too) in the same namespace allows only loopback, the DNS endpoint, and the allowlisted destination IPs/CIDRs. Hardcoded IPs, DNS-over-HTTPS, or a rebinding that slips past the name gate still hit this wall.
3. **No proxy** — the runtime's bubblewrap sandbox runs with networking left to the fence (no `--unshare-net`, no proxy), so the two layers compose without fighting over the network namespace.

pasta runs IPv4-only, without port forwarding in either direction and without mapping the gateway to the host: the namespace's `127.0.0.1` is its own, not the host's, so local host services are not reachable.

The fence is **fail-closed**: if any of `pasta`, `ip`, `unshare`, `nft`, `mount`, `readlink` (in `PATH`) or `/usr/bin/bash`, `/usr/bin/python3`, `/bin/sh` is missing, commands are blocked with the missing tool named; at startup a probe runs a fenced command with an empty allowlist and blocks all commands unless the fence comes up and stops both a direct connection and a name lookup; an allowlist entry the v1 fence cannot express is skipped (with a warning on the console, once per entry), not silently downgraded; an empty effective allowlist allows nothing.

v1 allowlist entry support (entries come from `allowedDomains`, same as the proxy model):

- exact domains (e.g. `registry.npmjs.org`) — resolved on the host when the command's fence is set up, pinned for that command's lifetime
- `*.domain` wildcards (e.g. `*.github.com`) — strict subdomains are resolved on demand by the fence's host-side upstream resolver and vouched into the egress ruleset per address; over-broad bases (a single label, as in `*.com`) are rejected
- IPv4 literals and CIDRs (e.g. `10.17.146.234`, `10.16.59.0/24`)
- *not supported yet*: `:port` suffixes, IPv6 — such entries are skipped with a warning

`deniedDomains` narrows the allowlist and takes precedence over it: denied exact domains and `*.domain` wildcards are never pinned, and names under an allowed wildcard that match a denial get NXDOMAIN at lookup time (e.g. `*.github.com` allowed, `evil.github.com` denied); denied IPv4 literals/CIDRs are dropped ahead of every allow rule (e.g. inside an allowed CIDR); and `*` (deny-all) disables every domain and wildcard entry while raw IP/CIDR entries stay effective — the same as the proxy model, where `*` matches names, not IP destinations. Wildcard subdomains are IPv4-only like the rest of the fence (AAAA lookups are answered empty).

Limitations: DNS is answered over UDP only; pinned addresses — and the addresses vouched for wildcard subdomains — are fixed for the command's lifetime, so a very long-running command does not follow DNS changes.

`fenced` takes precedence over `allowedDomains` for the *runtime* (the allowlist is consumed by the fence, not the proxy); filesystem sandboxing and the whole-sandbox switches behave exactly as with `disabled`. `fenced` and `network.disabled` are mutually exclusive (setting both is a config error); `allowUnixSockets`, `allowAllUnixSockets` and `allowLocalBinding` have no effect with `fenced` (Unix sockets stay blocked by the seccomp filter). The fence is Linux-only — on other platforms `fenced: true` blocks all commands with a message.

**SELinux note:** pasta normally runs in its own SELinux domain (`pasta_t`). If opencode itself runs with `no_new_privs` (e.g. started from inside another sandbox, or a systemd unit with `NoNewPrivileges=`), that domain transition is denied: pasta still works, but runs unconfined and SELinux reports an `nnp_transition nosuid_transition` denial for each command. The plugin warns about this at startup; start opencode without `no_new_privs` to avoid it.

### IP addresses and network ranges (CIDR)

`allowedDomains` and `deniedDomains` also accept IP literals and CIDR ranges, in addition to domains and `*.domain` wildcards:

```json
{
  "network": {
    "allowedDomains": ["10.22.86.0/24", "10.22.86.5", "2001:db8::/32", "[2001:db8::1]"],
    "deniedDomains": ["192.168.1.0/24"]
  }
}
```

Entry rules:

- IPv4: dotted literal or CIDR, optional `:port` suffix (`10.22.86.0/24:8080`)
- IPv6: unbracketed literal or CIDR (`2001:db8::1`, `2001:db8::/32` — same syntax as `deniedResolvedAddresses`); bracketed literals (`[2001:db8::1]`) remain accepted
- A `:port` suffix on an **IPv6** range is written bracketed, like a bracketed literal: `[2001:db8::/32]:8080` (the unbracketed `2001:db8::/32:8080` is an address ambiguity and is rejected)
- A CIDR entry matches IP-literal destinations only, never names. A *name* in `allowedDomains` (e.g. `*.corp`) may still resolve into an allowed network — the runtime's resolved-address check judges the final address (loopback, link-local, multicast, cloud-metadata and your own interface addresses stay denied unless explicitly allowed by an IP entry).

Two client-side caveats for **raw IP destinations** on private ranges (RFC1918, link-local):

- The sandbox forces `HTTP(S)_PROXY` into every sandboxed process and lists the RFC1918 blocks in `NO_PROXY`, so proxy-respecting clients (curl, git, …) try to dial the address *directly* and fail — the sandboxed network namespace has no route. Route such traffic through the sandbox proxy explicitly: a SOCKS5 client (SOCKS ignores `NO_PROXY`), or e.g. `curl --proxy "$HTTP_PROXY" --noproxy '' …`.
- Hostname destinations are unaffected: they are not in `NO_PROXY`, go through the proxy, and pass the allowlist by name.

CIDR support in the allow/deny lists is provided by a [local patch](#local-patch-against-anthropic-ai-sandbox-runtime) against `@anthropic-ai/sandbox-runtime`; the upstream feature request is [anthropics/sandbox-runtime#65](https://github.com/anthropics/sandbox-runtime/issues/65).

### Default restrictions

**Filesystem (deny-read)**:
- `~/.ssh`, `~/.gnupg`
- `~/.aws/credentials`, `~/.azure`, `~/.config/gcloud`, `~/.config/gh`
- `~/.kube`, `~/.docker/config.json`
- `~/.npmrc`, `~/.netrc`, `~/.env`

**Filesystem (allow-read)**:
- Empty by default

**Filesystem (allow-write)**:
- Project directory
- Git worktree (validated — unsafe paths like `/` are rejected)
- `/tmp`

**Network (allow-only)**:
- `registry.npmjs.org`, `*.npmjs.org`
- `registry.yarnpkg.com`
- `pypi.org`, `*.pypi.org`, `crates.io`, `*.crates.io`
- `github.com`, `*.github.com`
- `gitlab.com`, `*.gitlab.com`, `bitbucket.org`, `*.bitbucket.org`
- `api.openai.com`, `api.anthropic.com`
- `*.googleapis.com`

Everything else is **blocked by default**.

### Enforcement self-check

Initialization succeeding says nothing about the OS sandbox actually enforcing at spawn time. Before the first agent command runs (once per session), the plugin executes a probe under the sandbox: a write outside the allowed write paths and a read of a denied path must both fail. If either succeeds — or the probe cannot run — commands are **blocked** (fail closed) with the reason in the error message. On Linux this catches a broken bubblewrap setup up front instead of as a mysterious per-command failure; see [Linux prerequisites](#linux-prerequisites) for the fix.

## Configuration

Config files are stored outside the project directory (in `~/.config/opencode/` or `~/.config/opencode-sandbox/`) so that sandboxed commands cannot modify them. This prevents indirect prompt injection from weakening the sandbox by overwriting the config.

### Invalid config fails closed

A config source that exists but cannot be used — invalid JSON, or values of the wrong shape (`denyRead` must be an array of strings, `disabled` a boolean, …) — makes the plugin **block commands** with the reason in the error message, instead of silently falling back to weaker defaults. Unknown keys are ignored with a warning (they may be written for a newer plugin version). Fix the file or toggle the sandbox off to run unsandboxed while fixing it.

### Config file locations

The plugin searches for configuration in this order (first match wins):

1. **Environment variable** `OPENCODE_SANDBOX_CONFIG` (JSON string)
2. **Environment variable** `OPENCODE_SANDBOX_CONFIG_PATH` (path to a JSON config file)
3. **Per-project config** `~/.config/opencode/projects/<project-name>.sandbox.json`
4. **Legacy per-project config** `~/.config/opencode-sandbox/projects/<project-name>.json`
5. **Global config** `~/.config/opencode/sandbox.json`
6. **Legacy global config** `~/.config/opencode-sandbox/config.json`
7. **Built-in defaults**

The `<project-name>` is the basename of the project directory (e.g., `my-app` for `/home/user/projects/my-app`).

If `XDG_CONFIG_HOME` is set, it is used instead of `~/.config`.

### Example: Global config

```json
// ~/.config/opencode/sandbox.json
{
  "filesystem": {
    "denyRead": ["~/.ssh", "~/.aws/credentials"],
    "allowRead": ["~/.ssh/id_ed25519.pub"],
    "allowWrite": [".", "/tmp", "/var/data"],
    "denyWrite": [".env.production"]
  },
  "network": {
    "allowedDomains": [
      "registry.npmjs.org",
      "github.com",
      "*.github.com",
      "api.openai.com",
      "api.anthropic.com",
      "my-internal-api.company.com"
    ],
    "deniedDomains": ["malicious.example.com"]
  }
}
```

### Path precedence

Path precedence is inherited from `@anthropic-ai/sandbox-runtime`:

- Read: `allowRead` takes precedence over `denyRead`
- Write: `denyWrite` takes precedence over `allowWrite`, at any nesting depth (an `allowWrite` path inside a `denyWrite` directory stays denied)

### Example: allow git commit signing with SSH public key

If your Git workflow needs to read a public key (for example `~/.ssh/id_ed25519.pub`) while keeping `~/.ssh` blocked by default, re-allow only that file:

```json
// ~/.config/opencode/sandbox.json
{
  "filesystem": {
    "denyRead": [
      "~/.ssh",
      "~/.gnupg",
      "~/.aws/credentials",
      "~/.azure",
      "~/.config/gcloud",
      "~/.config/gh",
      "~/.kube",
      "~/.docker/config.json",
      "~/.npmrc",
      "~/.netrc",
      "~/.env"
    ],
    "allowRead": ["~/.ssh/id_ed25519.pub"]
  }
}
```

### Example: Per-project config

```json
// ~/.config/opencode/projects/my-app.sandbox.json
{
  "network": {
    "allowedDomains": ["my-internal-api.company.com"]
  }
}
```

### Environment variables

`OPENCODE_SANDBOX_CONFIG` holds the configuration inline as a JSON string:

```bash
OPENCODE_SANDBOX_CONFIG='{"filesystem":{"denyRead":["~/.ssh"]},"network":{"allowedDomains":["github.com"]}}' opencode
```

`OPENCODE_SANDBOX_CONFIG_PATH` points at an existing JSON config file instead:

```bash
OPENCODE_SANDBOX_CONFIG_PATH=~/.config/opencode/sandbox.json opencode
```

Example allowing only the SSH public key to be read:

```bash
OPENCODE_SANDBOX_CONFIG='{"filesystem":{"denyRead":["~/.ssh","~/.gnupg","~/.aws/credentials","~/.azure","~/.config/gcloud","~/.config/gh","~/.kube","~/.docker/config.json","~/.npmrc","~/.netrc","~/.env"],"allowRead":["~/.ssh/id_ed25519.pub"]}}' opencode
```

### Disable

```bash
OPENCODE_DISABLE_SANDBOX=1 opencode
```

Or in any config file:

```json
{
  "disabled": true
}
```

These switches turn off the *entire* sandbox (network and filesystem). To keep filesystem restrictions but drop only the network layer, see [Disable the network sandbox](#disable-the-network-sandbox).

### Toggle

The command palette offers **Toggle Sandbox**, which pauses and resumes sandboxing for the current project.

Paused state is stored per project under `~/.cache/opencode-sandbox/toggle/` and survives restarts. It automatically re-enables after 7 days, so a sandbox is never left paused indefinitely.

The status-bar badge reflects the current state: green `on`, yellow `paused`, subdued `off` — and updates immediately when toggled.

## How it works

The plugin hooks the shell creation path, which OpenCode invokes for every command the agent runs:

1. The command is wrapped with `SandboxManager.wrapWithSandbox()` — OS-level filesystem and network restrictions around the process tree.
2. The shell binary is swapped for a tiny shim (`~/.cache/opencode-sandbox/shim/`, or `$XDG_CACHE_HOME` when set) that executes the wrapped command through the original shell.

The command string itself is left untouched, so OpenCode's built-in permission rules, shell-safety scanning and directory authorization all evaluate the real command.

Every shell OpenCode creates programmatically is covered — the shell tool and session shells. Interactive TUI terminals are spawned outside this path and are not sandboxed. Sandbox mount points are cleaned up when OpenCode reports the shell has ended, including interrupted and timed-out commands.

A TUI entrypoint (`exports["./tui"]`, or `tui.ts` for local installs) adds a status-bar badge (`⊙ sandbox: on`) to the home and session footers, reflecting the sandbox state including palette toggles (see [Toggle](#toggle)). Enabling/disabling the `opencode-sandbox` plugin toggles the badge, the palette command and the sandbox together.

```
Agent → shell → [sandboxed execution] → Agent
```

The AI model interprets sandbox errors (like "Read-only file system" or "Connection blocked") directly from command output — no additional annotation layer needed.

Sandbox initialization is deferred until the first command, so the plugin does not interfere with OpenCode startup. Plugin diagnostics go to the OpenCode server log, prefixed with `[opencode-sandbox]`. Sandbox violations are correlated with each individual command, including concurrent or repeated ones.

### Windows status

`@anthropic-ai/sandbox-runtime` supports Windows through an argv-and-environment API that OpenCode's plugin interfaces do not expose. Until they can be connected safely, the plugin blocks Windows commands.

### Nested sandboxing (SRT ≥ 0.0.80)

Since SRT 0.0.80, a sandboxed command stays in the namespaces it was given: it can no longer create its own user or mount namespace. Tools that sandbox themselves that way — rootless `podman`/`buildah`, Chromium/Electron, a nested `bubblewrap`, `unshare -r` — stop working inside the sandbox. SRT can lift this with `allowNestedUserNamespaces: true`, but that is a runtime-level option this plugin does not (and will not) forward, so such workflows have to run with the sandbox [paused](#toggle) for the project.

### Failure behavior

If sandbox initialization or wrapping fails, the affected command is blocked.

### Local patch against @anthropic-ai/sandbox-runtime

The runtime's config schema only accepts domains, `*.domain` wildcards and IP literals in `network.allowedDomains` / `network.deniedDomains` — no CIDR ranges (upstream RFE: [anthropics/sandbox-runtime#65](https://github.com/anthropics/sandbox-runtime/issues/65)). This plugin therefore ships a local patch, `patches/@anthropic-ai+sandbox-runtime+0.0.81.patch`, that adds IP-literal/CIDR entries to both lists:

- config-time validation accepts the entries (same syntax as `deniedResolvedAddresses`),
- destination matching judges them by range membership (`net.BlockList`),
- the resolved-address guard receives them, so deny-CIDRs also block hostnames that resolve into the range.

Mechanics:

- `@anthropic-ai/sandbox-runtime` is **pinned to the exact version the patch was generated against** (`0.0.81`). A `postinstall` script runs `patch-package`, which applies the patch after every `bun install`; if it cannot (version bump, patch missing), it reports the failure instead of aborting the install, and the guardrail test below makes the gap visible.
- `test/network-cidr.test.ts` is a guardrail: it imports the installed dist files directly, so a missing patch (or a future SRT version without the feature) turns the suite red instead of letting CIDR entries be rejected at sandbox start.

Regenerating the patch for a newer SRT version: install the new version, apply the equivalent changes to `node_modules/@anthropic-ai/sandbox-runtime/dist/sandbox/{domain-pattern.js,domain-pattern.d.ts,sandbox-config.js}` (or port the patch with `filterdiff`/`git apply --3way`), then regenerate the file against a pristine tarball:

```sh
git diff --no-index pristine/node_modules patched/node_modules > patches/@anthropic-ai+sandbox-runtime+<version>.patch
```

…bump the dependency pin, and update the guardrail test's expected behavior if the upstream semantics changed. If the feature ships upstream, delete the patch, the pin (go back to a `^` range) and the `postinstall` hook — the guardrail test should then pass against the unpatched runtime.

### Test isolation note

`bun test` runs test files in one process by default, and `mock.module()` is process-global and never reset between files (oven-sh/bun#31316) — `test/plugin.test.ts` mocks `../src/probe`, which would break `test/probe.test.ts`'s imports in the same process. The `test` script therefore runs each test file in its own `bun test` invocation.

## Related

- [@anthropic-ai/sandbox-runtime](https://github.com/anthropic-experimental/sandbox-runtime) — The underlying sandbox engine
- [OpenCode Plugins Docs](https://opencode.ai/v2/docs/build/plugins) — How to create and use plugins
- [Claude Code Sandboxing](https://docs.claude.com/en/docs/claude-code/sandboxing) — Anthropic's sandboxing documentation
