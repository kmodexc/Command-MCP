# Repository Guidelines

## Project Structure & Module Organization

This is a Rust workspace with two binaries. `src/main.rs` starts the MCP server, `src/ui.rs` contains the egui desktop configuration UI, `src/ui_server.rs` owns UI child-process lifecycle and stderr capture, `src/commands.rs` implements built-in and configured tools plus HTTP/stdio transport, and `src/lib.rs` contains shared configuration and command metadata. Most unit tests are inline under `#[cfg(test)]`; `tests/http_server.rs` exercises the compiled server over HTTP. `README.md` documents runtime configuration and deployment. `Dockerfile` and `compose.yaml` provide the container workflow.

## Build, Test, and Development Commands

Use the stable Rust toolchain (Rust 1.99+).

```bash
cargo fmt --all                 # Format Rust code
cargo test                      # Run unit, component, and HTTP contract tests
cargo build --release           # Build release artifacts
cargo run --bin command-mcp -- server
cargo run --bin command-mcp-ui  # Start the desktop UI and local server
docker compose up --build       # Build and run the container server
```

Run `cargo fmt --all` and `cargo test` before submitting changes. HTTP behavior should be tested through MCP `initialize`, `tools/list`, and `tools/call` where relevant.

## Coding Style & Naming Conventions

Use `rustfmt` defaults, four-space indentation, idiomatic Rust naming, and descriptive error messages. MCP tool names must start with a letter and contain only letters, digits, `_`, or `-`; argument names use letters, digits, and `_`. Keep command execution typed and allowlist-based. Do not add generic shell execution or place secrets in tracked files.

## Testing Guidelines

Testing should:

1. Define acceptance criteria as observable outcomes.
2. Write a failing regression test before changing behavior.
3. Cover the full state matrix: new, changed, reloaded, enabled, disabled, invalid, and failed.
4. Test the real user boundary with the built artifact, using deterministic isolated fixtures.
5. Run the complete suite in CI for every change and keep escaped bugs as permanent regression tests.

## Commit & Pull Request Guidelines

Existing commits use short, lowercase summaries such as `rust rewrite and add UI`. Follow that concise style, using an imperative subject where practical. Pull requests should explain the user-visible behavior, identify configuration or security impact, and report `cargo fmt --all` and `cargo test` results. Include screenshots for meaningful UI changes and document any required environment variables or restart behavior.

## Security & Configuration

Keep API keys in `.env` with restrictive permissions and use bearer authentication for remote binds. Review configured SSH, SCP, and Docker tools as authority-bearing changes. Preserve host validation, bounded command arguments, output redaction, and the default-disabled tool posture.
