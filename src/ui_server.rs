use std::{
    collections::{BTreeMap, VecDeque},
    env,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use command_mcp::ssh::SshControlRequest;
use zeroize::Zeroize;

pub(crate) struct ServerLaunchConfig<'a> {
    pub binary: Option<&'a Path>,
    pub config_path: &'a Path,
    pub env_path: &'a Path,
    pub host: &'a str,
    pub port: u16,
    pub auth_enabled: bool,
    pub allow_unauthenticated_remote: bool,
    pub env_values: &'a BTreeMap<String, String>,
}

pub(crate) struct ServerExit {
    pub status: ExitStatus,
    pub stderr: String,
}

pub(crate) struct ServerProcess {
    child: Child,
    stdin: Option<std::process::ChildStdin>,
    control_events: Arc<Mutex<VecDeque<String>>>,
    stderr: Option<StderrCapture>,
}

struct StderrCapture {
    output: Arc<Mutex<StderrOutput>>,
    finished: Arc<AtomicBool>,
}

#[derive(Default)]
struct StderrOutput {
    text: String,
    error: Option<String>,
}

impl ServerProcess {
    pub fn start(config: &ServerLaunchConfig<'_>) -> Result<Self, String> {
        let binary = config
            .binary
            .map(Path::to_path_buf)
            .map(Ok)
            .unwrap_or_else(server_binary)?;
        if !binary.is_file() {
            let build = Command::new("cargo")
                .args(["build", "--quiet", "--bin", "command-mcp"])
                .output()
                .map_err(|error| format!("Could not build the server binary: {error}"))?;
            if !build.status.success() || !binary.is_file() {
                let details = command_output_details(&build.stdout, &build.stderr);
                return Err(format!(
                    "The server binary {} is missing and could not be built ({}).{} Set COMMAND_MCP_SERVER_BIN to a server executable.",
                    binary.display(),
                    build.status,
                    details
                ));
            }
        }

        let mut child = Command::new(&binary)
            .arg("server")
            .env("COMMAND_MCP_CONFIG", config.config_path)
            .env("COMMAND_MCP_ENV_FILE", config.env_path)
            .env("COMMAND_MCP_HOST", config.host)
            .env("COMMAND_MCP_PORT", config.port.to_string())
            .env("COMMAND_MCP_AUTH_ENABLED", config.auth_enabled.to_string())
            .env(
                "COMMAND_MCP_ALLOW_UNAUTHENTICATED_REMOTE",
                config.allow_unauthenticated_remote.to_string(),
            )
            .env(
                "COMMAND_MCP_API_KEY",
                config
                    .env_values
                    .get("COMMAND_MCP_API_KEY")
                    .cloned()
                    .unwrap_or_default(),
            )
            .env("COMMAND_MCP_CONTROL", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| {
                format!(
                    "Could not start {}: {error}. Set COMMAND_MCP_SERVER_BIN to the server executable.",
                    binary.display()
                )
            })?;
        let Some(stderr) = child.stderr.take() else {
            let kill_error = child.kill().err();
            let wait_error = child.wait().err();
            let cleanup = [kill_error, wait_error]
                .into_iter()
                .flatten()
                .map(|error| error.to_string())
                .collect::<Vec<_>>();
            return Err(if cleanup.is_empty() {
                "Could not capture the server's error output".into()
            } else {
                format!(
                    "Could not capture the server's error output: {}",
                    cleanup.join("; ")
                )
            });
        };
        let Some(stdout) = child.stdout.take() else {
            let kill_error = child.kill().err();
            let wait_error = child.wait().err();
            let cleanup = [kill_error, wait_error]
                .into_iter()
                .flatten()
                .map(|error| error.to_string())
                .collect::<Vec<_>>();
            return Err(if cleanup.is_empty() {
                "Could not capture the server control output".into()
            } else {
                format!(
                    "Could not capture the server control output: {}",
                    cleanup.join("; ")
                )
            });
        };

        let output = Arc::new(Mutex::new(StderrOutput::default()));
        let reader_output = Arc::clone(&output);
        let finished = Arc::new(AtomicBool::new(false));
        let reader_finished = Arc::clone(&finished);
        thread::spawn(move || {
            let mut text = String::new();
            let error = BufReader::new(stderr)
                .read_to_string(&mut text)
                .err()
                .map(|error| error.to_string());
            let mut captured = reader_output
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            captured.text = text;
            captured.error = error;
            reader_finished.store(true, Ordering::Release);
        });

        let control_events = Arc::new(Mutex::new(VecDeque::new()));
        let reader_events = Arc::clone(&control_events);
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if line.len() > 64 * 1024 {
                    continue;
                }
                let mut events = reader_events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if events.len() >= 128 {
                    events.pop_front();
                }
                events.push_back(line);
            }
        });

        let stdin = child.stdin.take();
        Ok(Self {
            child,
            stdin,
            control_events,
            stderr: Some(StderrCapture { output, finished }),
        })
    }

    pub fn send_control(&mut self, request: SshControlRequest) -> Result<(), String> {
        let mut encoded = serde_json::to_vec(&request)
            .map_err(|error| format!("Could not encode SSH control request: {error}"))?;
        encoded.push(b'\n');
        let result = self
            .stdin
            .as_mut()
            .ok_or_else(|| "The server control channel is closed".to_string())
            .and_then(|stdin| {
                stdin
                    .write_all(&encoded)
                    .and_then(|_| stdin.flush())
                    .map_err(|error| format!("Could not send SSH control request: {error}"))
            });
        encoded.zeroize();
        result
    }

    pub fn drain_control_events(&mut self) -> Vec<String> {
        let mut events = self
            .control_events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        events.drain(..).collect()
    }

    #[cfg(test)]
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn try_wait(&mut self) -> Result<Option<ServerExit>, String> {
        let Some(status) = self
            .child
            .try_wait()
            .map_err(|error| format!("Could not check the server process: {error}"))?
        else {
            return Ok(None);
        };
        let stderr = self
            .finish_stderr_capture()
            .unwrap_or_else(|error| error.to_string());
        self.stdin.take();
        Ok(Some(ServerExit { status, stderr }))
    }

    pub fn stop(mut self) -> Result<(), String> {
        self.stdin.take();
        let kill_error = self.child.kill().err();
        let wait_error = self.child.wait().err();
        let stderr_error = self.finish_stderr_capture().err();
        let mut errors = [kill_error, wait_error]
            .into_iter()
            .flatten()
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        if let Some(error) = stderr_error {
            errors.push(error);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    fn finish_stderr_capture(&mut self) -> Result<String, String> {
        let Some(capture) = self.stderr.take() else {
            return Ok(String::new());
        };
        for _ in 0..100 {
            if capture.finished.load(Ordering::Acquire) {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        let output = capture
            .output
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(error) = &output.error {
            Err(format!(
                "{}\nCould not read server error output: {error}",
                output.text.trim()
            ))
        } else {
            Ok(output.text.clone())
        }
    }
}

fn server_binary() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("COMMAND_MCP_SERVER_BIN") {
        return Ok(PathBuf::from(path));
    }
    let mut path = env::current_exe()
        .map_err(|error| format!("Could not locate the UI executable: {error}"))?;
    path.set_file_name(if cfg!(windows) {
        "command-mcp.exe"
    } else {
        "command-mcp"
    });
    Ok(path)
}

fn command_output_details(stdout: &[u8], stderr: &[u8]) -> String {
    let stdout = String::from_utf8_lossy(stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(stderr).trim().to_string();
    match (stdout.is_empty(), stderr.is_empty()) {
        (true, true) => String::new(),
        (false, true) => format!(" Build output: {stdout}."),
        (true, false) => format!(" Build error output: {stderr}."),
        (false, false) => format!(" Build output: {stdout}. Build error output: {stderr}."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::{Mutex, OnceLock},
        thread,
    };

    fn environment_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[cfg(unix)]
    fn script(label: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = env::temp_dir().join(format!(
            "command-mcp-ui-server-{label}-{}-{}.sh",
            std::process::id(),
            thread::current().name().unwrap_or("test")
        ));
        fs::write(&path, body).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn launch<'a>(values: &'a BTreeMap<String, String>) -> ServerLaunchConfig<'a> {
        ServerLaunchConfig {
            binary: None,
            config_path: Path::new("config.toml"),
            env_path: Path::new("env"),
            host: "127.0.0.1",
            port: 8000,
            auth_enabled: true,
            allow_unauthenticated_remote: false,
            env_values: values,
        }
    }

    #[cfg(unix)]
    #[test]
    fn starts_and_stops_a_server_process() {
        let _lock = environment_lock();
        let binary = script("lifecycle", "#!/bin/sh\nexec sleep 2\n");
        let values = BTreeMap::from([(String::from("COMMAND_MCP_API_KEY"), String::from("key"))]);
        let mut launch = launch(&values);
        launch.binary = Some(&binary);
        let server = ServerProcess::start(&launch).unwrap();
        assert!(server.id() > 0);
        server.stop().unwrap();
        let _ = fs::remove_file(binary);
    }

    #[cfg(unix)]
    #[test]
    fn captures_large_stderr_without_blocking() {
        let _lock = environment_lock();
        let binary = script(
            "stderr",
            "#!/bin/sh\ni=0\nwhile [ $i -lt 20000 ]; do echo server-output-$i >&2; i=$((i + 1)); done\nexit 1\n",
        );
        let values = BTreeMap::from([(String::from("COMMAND_MCP_API_KEY"), String::from("key"))]);
        let mut launch = launch(&values);
        launch.binary = Some(&binary);
        let mut server = ServerProcess::start(&launch).unwrap();
        for _ in 0..100 {
            if let Some(exit) = server.try_wait().unwrap() {
                assert!(!exit.status.success());
                assert!(exit.stderr.contains("server-output-19999"));
                let _ = fs::remove_file(binary);
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("server did not exit after writing stderr");
    }
}
