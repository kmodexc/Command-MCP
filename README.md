# Command MCP

An allowlist-first Rust MCP server for exposing your own commands to agents over
MCP Streamable HTTP. It serves MCP at `/mcp` and includes a small Rust/egui
desktop configuration UI.

The default server has **no generic shell-execution tool**. Every capability is a
typed Rust method with a generated MCP schema, making the agent's authority
visible and reviewable in source control. An unrestricted SSH tool is available
as a separate, explicit opt-in command and is disabled by default.

## Quick start

Requires Rust 1.99+.

```bash
# Put a long random value in COMMAND_MCP_API_KEY before exposing it beyond localhost.
# If this is omitted, the UI/server writes a cryptographically random value to
# the platform application configuration directory.
export COMMAND_MCP_API_KEY=replace-with-a-long-random-secret
cargo run --bin command-mcp -- server
```

Start the desktop UI:

```bash
cargo run --bin command-mcp-ui
```

The UI starts and owns the local MCP server process. It shows built-in commands
in groups with quick enable-all and disable-all controls, alongside configured
tools in a collapsible tree catalog. New configurations keep all predefined
commands disabled until you explicitly enable them. Saving a change writes the
configuration to the platform application configuration directory and clearly
marks the server as needing a restart; use the restart button to apply it.

Connect an MCP client to `http://127.0.0.1:8000/mcp`. If an API key is configured,
send it as `Authorization: Bearer <key>`.

Check readiness:

```bash
curl http://127.0.0.1:8000/healthz
```

## Connect multiple Codex agents from a workspace

Run one Command MCP server and configure every agent to connect to the same
Streamable HTTP endpoint. You do not need to start one server per agent. With
the default stateless HTTP mode, independent agents can open concurrent MCP
sessions and call the read-only tools at the same time.

For Codex, place the MCP configuration inside the trusted repository. All Codex
agents opened in that workspace will inherit it:

```text
your-workspace/
├── .codex/
│   └── config.toml
├── .env
└── ...
```

Create `.codex/config.toml` with:

```toml
[mcp_servers.os_debug]
url = "http://127.0.0.1:8000/mcp"
bearer_token_env_var = "COMMAND_MCP_API_KEY"
enabled = true
tool_timeout_sec = 45
```

Keep the token in `.env`, not in the tracked TOML file:

```dotenv
COMMAND_MCP_API_KEY=replace-with-a-long-random-secret
```

The Command MCP server reads `.env` itself. Codex also needs the token in its
process environment so it can authenticate to the server. Start Codex from a
shell that has loaded the workspace environment:

```bash
set -a
source .env
set +a
codex
```

After trusting the project, restart Codex or open a new workspace session. Use
`/mcp` in Codex to confirm that `os_debug` is connected. The Codex CLI, IDE
extension, and desktop app use the same project configuration on that Codex
host.

Multiple agents in the workspace then share the project-scoped connection:

```text
Workspace agent A ─┐
                   ├── .codex/config.toml ── Command MCP ── host diagnostics
Workspace agent B ─┘
```

Other agent applications can use the same server, although their workspace
configuration filename and syntax may differ. Each client needs the same three
values:

- transport: MCP Streamable HTTP
- URL: `http://127.0.0.1:8000/mcp`
- header: `Authorization: Bearer <COMMAND_MCP_API_KEY>`

If the agents run on other machines, bind the server to an appropriate private
interface instead of loopback:

```dotenv
COMMAND_MCP_HOST=0.0.0.0
COMMAND_MCP_API_KEY=replace-with-a-long-random-secret
```

Then configure each agent with the externally reachable HTTPS endpoint, for
example `https://diagnostics.example.net/mcp`. Put a trusted TLS reverse proxy in
front of the server; do not send its bearer token over untrusted plain HTTP.
Restrict network access to the agent machines where possible.

The built-in authentication supports one static key, so all connected agents
have the same tool permissions and their calls are not attributed separately.
Use separate server instances with different keys when agents need different
authority. Use an OAuth-capable MCP gateway when you need per-agent identities,
revocation, or an audit trail.

Built-in tools include `ls`, `cat`, `ps`, `journalctl`, `lsusb`, `usb_topology`, `lspci`,
`dmesg`, `xrandr`, `wayland_info`, `wlr_randr`, `kscreen_doctor`, `drm_info`,
`jay_randr`, `gnome_display_state`, `modetest`, `boltctl`, `uname`,
`kernel_cmdline`, `kernel_modules`, `typec_state`, `ubuntu_drivers`, `nvidia_smi`,
`nvidia_modinfo`, `nvidia_driver_state`, `secure_boot_state`, `dkms_status`, `nvidia_packages`,
`prime_select`, `supergfx_mode`, `module_info`, `pci_device_state`,
`thunderbolt_state`, `drm_connector_state`, `usb_authorization_state`, and
`display_diagnostics`. They
return standard output, standard error, exit status, timestamps, duration, host,
execution classification, timeout status, and truncation metadata. Arguments are
constrained, subprocesses have timeouts, and combined output retained in memory is
capped at 200,000 bytes. A missing optional system utility is reported with exit
code 127. Output redaction covers labeled credential fields, bearer tokens,
cookies, and private-key blocks, and results report the redaction count and
categories. Treat this as defense in depth rather than a guarantee that arbitrary
secret formats will be recognized.
Use `ps` with a case-insensitive query to search process command lines; its
optional `limit` argument defaults to 100 and is capped at 1,000 results.

`ls` and `cat` resolve paths and only allow access below
`COMMAND_MCP_READ_ROOTS`, which defaults to the server's working directory. Use a
comma-separated list to approve additional locations such as a specific log
directory. Symlinks are resolved before the policy check, and `cat` only reads
regular files. Common credential locations and filenames are denied unless
`COMMAND_MCP_ALLOW_SENSITIVE_FILE_READS=true` is explicitly configured.

## Configure tools in the UI

Select `+ New` in the configured tools section to create a tool. Each tool has
a name, description, timeout, an enabled switch, and a command template. A
template such as `echo {message}` creates a generated MCP input schema with a
`message` field. The UI supports string, integer, number, and boolean
parameters, and inserts each value into a single process argument without
using a local shell.

Configured tools have four kinds:

- `Local command` runs an executable on the MCP server host.
- `SSH command` runs the configured command through the local OpenSSH client,
  or through a persistent russh session when password authentication is chosen.
  Its authentication choices are SSH agent, identity file/FIDO2 key, and
  password.
- `SCP file upload` uploads a UI-selected local file with `scp`; the LLM
  supplies the remote destination parameter.
- `Dockerfile command` builds the configured Dockerfile and runs the rendered
  command in the resulting container. The UI edits the Dockerfile as text and
  stores it under the platform's application data directory, while the build
  context remains a separately selected directory.

SSH tools use the local SSH agent by default; passwords and private key contents
are never stored in the configuration. You can select an identity file or FIDO2
key path as a fallback, but a readable unencrypted key file must be treated as
a credential. For unattended use, load a dedicated restricted key into the
agent with a short lifetime, for example `ssh-add -t 1h ~/.ssh/command-mcp`.
The SSH and SCP tools use batch mode, disable agent forwarding and TTY
allocation, and require the remote host to already exist in `known_hosts`.
They do not accept new host keys automatically. SCP and SSH destinations are
supplied to the OpenSSH client as arguments. Docker tools require `docker` in
the server process PATH. These configurable tools are disabled by default until
explicitly enabled in the UI.

SSH password authentication requires the SSH user and a pinned SHA-256 host fingerprint in
the form `SHA256:...`. The UI sends the password over a private pipe to the
UI-owned local server; it is wrapped in a zeroizing type, used for the one-time
authentication exchange, and never written to the configuration. The session
closes automatically after 15 minutes by default, or sooner when you revoke it
or close the UI. The server rejects commands until the session has been
connected. Keep the MCP bearer token protected as well: anyone who can call the
MCP endpoint can use an enabled password-session tool while its access session
is open.

The application uses russh 0.64.1. The application-owned password buffers are
zeroized on destruction, but full memory erasure also depends on the russh
packet-buffer fix being applied; use the project fork or a released russh
version containing that fix when handling high-value credentials.

Docker tools can receive secrets from the environment file without putting
secret values in the Docker command arguments. Add variables such as
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `API_TOKEN` in the
environment editor, then add their names to the Docker tool's “Secrets passed
into the container” list. The server passes them with Docker's `--env KEY`
form and redacts configured secret values from returned output.

The “Server and environment” editor controls the environment file, bind host,
port, bearer authentication, generated API password, and unauthenticated remote
bind approval. Saving changes shows “Restart required”; use “Restart now” to
apply them. The API password is masked until “Show” is selected.

The configuration and API password are stored outside the project directory.
On Linux the configuration is under `$XDG_CONFIG_HOME/command-mcp` or
`~/.config/command-mcp`; on Windows it is under `%APPDATA%\command-mcp`; macOS
uses `~/Library/Application Support/command-mcp`. Set
`COMMAND_MCP_CONFIG_DIR` to choose a different configuration directory.

Dockerfile content is stored outside `config.toml`. On Linux it is under
`$XDG_DATA_HOME/command-mcp/dockerfiles` or
`~/.local/share/command-mcp/dockerfiles`; on Windows it is under
`%LOCALAPPDATA%\command-mcp\dockerfiles`; macOS uses
`~/Library/Application Support/command-mcp/dockerfiles`. Set
`COMMAND_MCP_DATA_DIR` to choose a different application data root. Existing
Dockerfile paths are imported into the managed location when the tool is opened
in the UI.

For a USB-C monitor issue, start with `display_diagnostics`. It returns a structured
snapshot of the USB tree, PCI driver bindings, DRM state, Type-C Alt Modes, loaded
kernel modules, NVIDIA installation and runtime state, DKMS, Secure Boot, PRIME and
ASUS GPU modes, USB authorization, USB4/Thunderbolt state, relevant current-boot
kernel events, and machine-readable findings in one call. For narrower
follow-up checks, use `uname`, `lsusb`, `usb_topology`, `lspci`, `kernel_modules`,
`kernel_cmdline`, `typec_state`,
`wayland_info`, `drm_info`, `modetest`, `boltctl`, and `journalctl` with
`kernel_only=true` and a grep such as `typec|thunderbolt|drm|displayport|usb`.
On Ubuntu's default GNOME desktop, use `gnome_display_state` to query Mutter and
`ubuntu_drivers` to check driver recommendations. Use `wlr_randr` on
Sway/wlroots or `kscreen_doctor` on KDE Plasma. `xrandr` usually reports only
XWayland state and is not authoritative for native Wayland outputs.

For Jay, use `jay_randr`; current Jay versions expose DRM devices, connectors,
output modes, and renderer information through `jay --json randr`. On an NVIDIA
system, also use `nvidia_smi`, `nvidia_modinfo`, `nvidia_packages`, `dkms_status`,
`prime_select`, `supergfx_mode`, `secure_boot_state`, and a kernel-only `journalctl`
query. Jay stores its own logs below
`~/.local/share/jay/log/jay`, which can be inspected with the bounded `ls` and
`cat` tools.

These commands inspect the machine where the MCP server process runs. A container
does not automatically have access to the host journal, display session, or
hardware devices; grant only the specific host resources required, or run the
server directly on the machine being diagnosed. GNOME/Wayland queries must run
as the logged-in desktop user with that session's `XDG_RUNTIME_DIR`,
`WAYLAND_DISPLAY`, and D-Bus environment. The same-user/session requirement also
applies to `jay_randr`; a server launched independently at `multi-user.target`
will not automatically inherit Jay's later session environment.

## Add a built-in command

Add a typed async method with `#[tool(...)]` to `src/commands.rs`, derive
`Deserialize` and `JsonSchema` for any argument struct, then add its name and
description to `COMMAND_SPECS` in `src/lib.rs`. The MCP schema is generated
from the Rust argument type. Use configured tools in the UI when the command
should be editable without recompiling the server.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `COMMAND_MCP_HOST` | `127.0.0.1` | TCP bind address |
| `COMMAND_MCP_PORT` | `8000` | TCP port |
| `COMMAND_MCP_API_KEY` | empty | Static bearer token; use only behind TLS |
| `COMMAND_MCP_AUTH_ENABLED` | `true` | Require the bearer API password |
| `COMMAND_MCP_ENV_FILE` | platform config directory (`.env`) | Environment file used for authentication and Docker secrets; explicit override |
| `COMMAND_MCP_READ_ROOTS` | current working directory | Comma-separated roots available to `ls` and `cat` |
| `COMMAND_MCP_CONFIG` | platform config directory (`config.toml`) | Built-in command and configured tool catalog; explicit override |
| `COMMAND_MCP_CONFIG_DIR` | platform config directory | Configuration directory override |
| `COMMAND_MCP_UI_PORT` | `COMMAND_MCP_PORT` or `8000` | Port used by the UI-owned local server |
| `COMMAND_MCP_SERVER_BIN` | sibling `command-mcp` binary | Server executable launched by the UI |
| `COMMAND_MCP_ALLOW_UNAUTHENTICATED_REMOTE` | `false` | Permit a non-loopback bind without an API key |
| `COMMAND_MCP_ALLOW_SENSITIVE_FILE_READS` | `false` | Permit `ls`/`cat` access to common credential paths |
| `COMMAND_MCP_DATA_DIR` | platform application data directory | Root directory for managed Dockerfile content |

## Production notes

- Terminate TLS at a trusted reverse proxy. Never transmit the static key over HTTP
  on an untrusted network.
- Prefer full MCP OAuth 2.1 when multiple users or delegated identities are needed;
  the API key mode is deliberately a small single-tenant deployment option.
- Run as an unprivileged user with a read-only filesystem and grant only the
  directories/network destinations required by specific commands.
- Treat every command argument as hostile. Bound strings and collections, normalize
  paths, set outbound request timeouts, and make destructive actions idempotent.
- Avoid unbounded command strings and `shell=True`. Configured templates are
  parsed into bounded argument lists; SSH templates quote the generated remote
  command and SCP destinations accept only safe path characters.
- Keep the default localhost bind unless a reverse proxy or container network
  actually needs external access.
- A non-loopback bind requires an API key unless the explicit unsafe override is
  enabled for an isolated trusted network.

## Docker

```bash
export COMMAND_MCP_API_KEY="$(openssl rand -hex 32)"
docker compose up --build
```

The compose service drops Linux capabilities, uses a read-only root filesystem,
and publishes only to the host loopback interface.

## Development

```bash
cargo fmt --all
cargo test
cargo check --bins
```
