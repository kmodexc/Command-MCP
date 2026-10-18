#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ui_binary="$repo_root/target/release/command-mcp-ui"
server_binary="$repo_root/target/release/command-mcp"

cargo build --release --manifest-path "$repo_root/Cargo.toml" --bin command-mcp-ui --bin command-mcp

if [[ ! -x "$ui_binary" || ! -x "$server_binary" ]]; then
    printf 'release binaries were not produced under %s/target/release\n' "$repo_root" >&2
    exit 1
fi

applications_dir="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
desktop_file="$applications_dir/command-mcp.desktop"
mkdir -p "$applications_dir"

tmp_file=$(mktemp "${desktop_file}.XXXXXX")
trap 'rm -f "$tmp_file"' EXIT
cat >"$tmp_file" <<EOF
[Desktop Entry]
Type=Application
Name=Command MCP
Comment=Configure and run the Command MCP server
Exec=$ui_binary
TryExec=$ui_binary
Path=$HOME
Icon=utilities-terminal
Terminal=false
Categories=Utility;Development;
StartupNotify=true
EOF
chmod 0644 "$tmp_file"
mv "$tmp_file" "$desktop_file"
trap - EXIT

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$applications_dir" >/dev/null 2>&1 || true
fi

printf 'Installed %s\n' "$desktop_file"
