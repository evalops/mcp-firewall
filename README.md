# MCP Firewall

A small MCP (Model Context Protocol) firewall that proxies JSON-RPC and enforces allow/deny policies for tools, resources, prompts, and methods. It can run as a stdio wrapper or as a streamable HTTP reverse proxy, and includes a clean local GUI for policy edits, history, templates, and live logs.

## Quick start (stdio)

Build:

```sh
go build ./cmd/mcp-firewall
```

Run as a wrapper around a real MCP server:

```sh
./mcp-firewall --policy policy.example.yaml -- <server-command> <args>
```

## GUI (local dashboard)

Serve the GUI while running stdio:

```sh
./mcp-firewall --ui 127.0.0.1:8081 --policy policy.example.yaml -- <server-command> <args>
```

Open `http://127.0.0.1:8081/ui`.
The policy editor shows diff counts, local warnings, a library modal with diff view, and history in the Advanced drawer. The dashboard includes a \"Top blocked by\" chart, log table filters, CSV exports, and filter presets.

Enable policy edits from the GUI:

```sh
./mcp-firewall --ui 127.0.0.1:8081 --policy policy.example.yaml --policy-write -- <server-command>
```

Lock down the GUI/API with a token:

```sh
./mcp-firewall --ui 127.0.0.1:8081 --api-token YOUR_TOKEN --policy policy.example.yaml -- <server-command>
```

Adjust how many versions to keep:

```sh
./mcp-firewall --ui 127.0.0.1:8081 --policy-history 50 --policy policy.example.yaml -- <server-command>
```

## Host-wide discovery + install

Scan common MCP host config locations (Claude Desktop, Cursor, VS Code) and workspace roots:

```sh
./mcp-firewall --host-scan --host-root . --host-root ~/Projects
```

Wrap discovered stdio servers (and proxy HTTP servers) with the firewall:

```sh
./mcp-firewall --host-install \\
  --policy policy.example.yaml \\
  --no-network \\
  --allow-bin git \\
  --host-root . \\
  --host-http-listen 127.0.0.1:17880 \\
  --host-http-path /mcp
```

The installer writes a routes file (default `~/.mcp-firewall/routes.json`) for HTTP upstreams and flips on a global toggle file (default `~/.mcp-firewall/enabled`).

Run the HTTP proxy for those routes:

```sh
./mcp-firewall --listen 127.0.0.1:17880 --routes ~/.mcp-firewall/routes.json --path /mcp --ui 127.0.0.1:8081
```

## Global toggle

Use an enabled file to flip enforcement on/off:

```sh
./mcp-firewall --enabled-file ~/.mcp-firewall/enabled --enable
./mcp-firewall --enabled-file ~/.mcp-firewall/enabled --disable
./mcp-firewall --enabled-file ~/.mcp-firewall/enabled --status
```

When `--enabled-file` is set on the wrapper, missing file = bypass, present file = enforce. The GUI status panel includes a toggle button when this is configured.

## HTTP mode (streamable HTTP)

Run the firewall as a reverse proxy in front of an MCP HTTP server:

```sh
./mcp-firewall --listen 127.0.0.1:8080 \
  --upstream http://127.0.0.1:9000/mcp \
  --path /mcp \
  --ui-path /ui \
  --allow-origins http://localhost:1234 \
  --policy policy.example.yaml
```

Open `http://127.0.0.1:8080/ui`.

Notes:
- `--allow-origins` is strongly recommended for browser clients.
- The firewall expects streamable HTTP and supports SSE responses.
- Use `--routes ~/.mcp-firewall/routes.json` to run in multi-upstream mode (paths like `/mcp/<id>`).

## Discover allowlist policy

Generate an allowlist from a server's exact tool/prompt/resource names:

```sh
./mcp-firewall --discover --server-framing line -- <server-command> <args> > policy.discovered.yaml
```

## Example: "message + CLI only"

Use the policy below to allow only CLI-like tools and local resources. Everything else is blocked.

```yaml
methods:
  # Only restrict these if needed; leaving allow empty keeps defaults permissive.
  deny: []

tools:
  # Allow only CLI tools. Adjust tool names to match your server.
  allow:
    - "cli.*"
    - "shell.*"
  deny: []

resources:
  # Allow only local/file-ish resources.
  allow_schemes:
    - "file"
    - "local"
  deny_schemes:
    - "http"
    - "https"
    - "smtp"
    - "imap"
    - "s3"

prompts:
  # Allow prompts by name if you expose any.
  allow: []
  deny: []
```

Hardening (block outbound network from the MCP server process):

```sh
./mcp-firewall --no-network --policy policy.example.yaml -- <server-command> <args>
```

Notes:
- `--no-network` only applies to stdio/discover modes because HTTP upstreams run elsewhere.
- On macOS this uses `sandbox-exec`; on Linux it attempts `firejail` or `unshare`. Use `--no-network-best-effort` to proceed if no sandbox is available.
- Use `--allow-bin git,ls` (repeatable) to restrict which executables the server can spawn; this is enforced with `sandbox-exec` or `firejail`.

## Inspection (prompt-injection heuristics)

Enable inspection to flag suspicious outputs from tools/resources/prompts:

```sh
./mcp-firewall --inspect --inspect-threshold 5 --inspect-excerpt --policy policy.example.yaml -- <server-command>
```

Optional hardening:
- `--inspect-redact` replaces suspicious text with `[redacted by mcp-firewall]`.
- `--inspect-block` blocks responses that cross the threshold.

## Policy model

- `methods`: JSON-RPC method names (e.g., `tools/call`, `resources/read`).
- `tools`: tool names in `tools/list` or `tools/call`.
- `resources`: resource URI patterns and scheme allow/deny lists.
- `prompts`: prompt names in `prompts/list` or `prompts/get`.

Rules are applied in this order:
1. Deny list
2. Allow list (if non-empty)
3. Otherwise allowed

Patterns use glob matching (`*`, `?`).

## Framing (stdio)

MCP stdio uses line-delimited JSON in the current spec. This proxy defaults to `--server-framing line`, but you can switch to LSP-style framing with `--server-framing lsp` if needed.

## Logging

Blocked traffic is logged as JSON lines to stderr by default. Use `--log` to write to a file and `--log-allowed` to log allowed events too. Suspicious outputs create `decision=flagged` log entries with `suspicionScore` and `suspicionFlags` fields. The GUI reads logs via SSE from `/api/logs/stream` and renders a table with filters.

## Limitations

- Allowing a CLI tool still allows the model to fetch external data through that tool.
- HTTP mode is a reverse proxy for streamable HTTP servers (no legacy SSE transport adapter).
- Prompt-injection detection is heuristic and can produce false positives or negatives.

## Files

- `cmd/mcp-firewall/main.go` - CLI entry point
- `internal/firewall/*` - proxy, policy, discovery, HTTP logic, and GUI assets
- `policy.example.yaml` - starter policy
