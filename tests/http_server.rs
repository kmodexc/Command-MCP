use std::{
    fs,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use command_mcp::{
    ConfiguredTool, ConfiguredToolKind, ServerConfig, ToolParameter, save_command_config,
    save_env_file,
};
use serde_json::Value;

struct RunningServer {
    child: Child,
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn test_root() -> PathBuf {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "command-mcp-http-artifact-{}-{timestamp}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn configured_tool(name: &str, enabled: bool) -> ConfiguredTool {
    ConfiguredTool {
        name: name.into(),
        description: format!("{name} integration test tool."),
        kind: ConfiguredToolKind::Local,
        enabled,
        command: "printf '%s' {message}".into(),
        parameters: vec![ToolParameter {
            name: "message".into(),
            description: "Text to print.".into(),
            type_name: "string".into(),
            required: true,
        }],
        ..ConfiguredTool::default()
    }
}

fn start_server(root: &std::path::Path) -> (RunningServer, String) {
    let port = free_port();
    let config_path = root.join("command-mcp.toml");
    let env_path = root.join("command-mcp.env");
    let tools = vec![
        configured_tool("artifact_enabled", true),
        configured_tool("artifact_disabled", false),
    ];
    save_command_config(
        &config_path,
        &Default::default(),
        &tools,
        &ServerConfig {
            host: "127.0.0.1".into(),
            port,
            auth_enabled: true,
            env_file: env_path.display().to_string(),
            allow_unauthenticated_remote: false,
        },
    )
    .unwrap();
    save_env_file(
        &env_path,
        &[("COMMAND_MCP_API_KEY".into(), "artifact-key".into())]
            .into_iter()
            .collect(),
    )
    .unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_command-mcp"))
        .arg("server")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("COMMAND_MCP_CONFIG", &config_path)
        .env("COMMAND_MCP_ENV_FILE", &env_path)
        .env("COMMAND_MCP_HOST", "127.0.0.1")
        .env("COMMAND_MCP_PORT", port.to_string())
        .env("COMMAND_MCP_AUTH_ENABLED", "true")
        .env("COMMAND_MCP_API_KEY", "artifact-key")
        .env("COMMAND_MCP_READ_ROOTS", root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    (RunningServer { child }, format!("127.0.0.1:{port}"))
}

fn http_request(
    address: &str,
    method: &str,
    path: &str,
    body: Option<&Value>,
    api_key: Option<&str>,
) -> io::Result<(u16, Value)> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let body_text = body.map(Value::to_string).unwrap_or_default();
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n");
    if !body_text.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str("Accept: application/json, text/event-stream\r\n");
        request.push_str("MCP-Protocol-Version: 2025-06-18\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", body_text.len()));
    }
    if let Some(api_key) = api_key {
        request.push_str(&format!("Authorization: Bearer {api_key}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&body_text);
    stream.write_all(request.as_bytes())?;

    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end;
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "HTTP response ended before headers",
            ));
        }
        response.extend_from_slice(&buffer[..read]);
        if let Some(position) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            header_end = position + 4;
            break;
        }
    }

    let headers = String::from_utf8_lossy(&response[..header_end]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing HTTP status"))?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then_some(value.trim())
        })
        .and_then(|length| length.parse::<usize>().ok())
        .unwrap_or(0);
    let chunked = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .any(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        });
    if chunked || content_length == 0 {
        stream.read_to_end(&mut response)?;
    } else {
        while response.len() < header_end + content_length {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            response.extend_from_slice(&buffer[..read]);
        }
    }
    let body = if chunked {
        decode_chunked(&response[header_end..])?
    } else {
        response[header_end..header_end + content_length].to_vec()
    };
    let json = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
    };
    Ok((status, json))
}

fn decode_chunked(mut input: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk header"))?;
        let size_text = input[..line_end]
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or_default();
        let size = usize::from_str_radix(
            std::str::from_utf8(size_text)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
                .trim(),
            16,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(output);
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid chunk body",
            ));
        }
        output.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

fn wait_until_healthy(address: &str) {
    for _ in 0..80 {
        if let Ok((status, _)) = http_request(address, "GET", "/healthz", None, None)
            && status == 200
        {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("server did not become healthy at {address}");
}

#[test]
fn compiled_server_serves_enabled_custom_tools_over_http() {
    let root = test_root();
    let (_server, address) = start_server(&root);
    wait_until_healthy(&address);

    let initialize = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "artifact-test", "version": "1"}
        }
    });
    let (status, initialize_body) = http_request(
        &address,
        "POST",
        "/mcp",
        Some(&initialize),
        Some("artifact-key"),
    )
    .unwrap();
    assert_eq!(status, 200);
    assert!(initialize_body["result"]["capabilities"].is_object());

    let list = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    let (status, list_body) =
        http_request(&address, "POST", "/mcp", Some(&list), Some("artifact-key")).unwrap();
    assert_eq!(status, 200);
    let tools = list_body["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0]["name"], "artifact_enabled");

    let call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "artifact_enabled",
            "arguments": {"message": "from compiled HTTP server"}
        }
    });
    let (status, call_body) =
        http_request(&address, "POST", "/mcp", Some(&call), Some("artifact-key")).unwrap();
    assert_eq!(status, 200);
    assert!(
        call_body["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("from compiled HTTP server")
    );

    let disabled_call = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "artifact_disabled",
            "arguments": {"message": "must not run"}
        }
    });
    let (status, disabled_body) = http_request(
        &address,
        "POST",
        "/mcp",
        Some(&disabled_call),
        Some("artifact-key"),
    )
    .unwrap();
    assert_eq!(status, 200);
    assert_eq!(disabled_body["error"]["code"], -32602);
    assert_eq!(disabled_body["error"]["message"], "tool not found");

    fs::remove_dir_all(root).unwrap();
}
