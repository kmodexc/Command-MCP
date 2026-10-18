use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use russh::keys::{HashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect, client};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter},
    sync::Mutex,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroize;

use crate::{ConfiguredTool, ConfiguredToolKind, SshAuthentication, commands::McpServer};

const MAX_OUTPUT_BYTES: usize = 200_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum SshControlRequest {
    Connect {
        tool: String,
        password: SensitiveString,
    },
    Revoke {
        tool: String,
    },
    RevokeAll,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SshControlEvent {
    Connected {
        tool: String,
    },
    Revoked {
        tool: String,
    },
    Error {
        tool: Option<String>,
        message: String,
    },
}

pub struct SensitiveString(String);

impl SensitiveString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for SensitiveString {
    fn default() -> Self {
        Self(String::new())
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SensitiveString(REDACTED)")
    }
}

impl Serialize for SensitiveString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SensitiveString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone)]
pub struct SshExecutionResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub timed_out: bool,
}

#[derive(Debug)]
struct HostKeyChecker {
    fingerprint: String,
}

impl client::Handler for HostKeyChecker {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(server_public_key
            .public_key()
            .fingerprint(HashAlg::Sha256)
            .to_string()
            == self.fingerprint)
    }
}

type SshHandle = client::Handle<HostKeyChecker>;

struct ActiveSshSession {
    expires_at: Instant,
    cancel: CancellationToken,
    handle: Mutex<Option<SshHandle>>,
}

impl ActiveSshSession {
    async fn close(&self) {
        self.cancel.cancel();
        let Some(handle) = self.handle.lock().await.take() else {
            return;
        };
        let _ = handle
            .disconnect(Disconnect::ByApplication, "session expired", "en")
            .await;
    }

    async fn execute(
        &self,
        command: String,
        timeout_seconds: u64,
    ) -> Result<SshExecutionResult, String> {
        let started_at = Utc::now();
        let started = Instant::now();
        let remaining = self.expires_at.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("SSH access session has expired".into());
        }
        let command_timeout = remaining.min(Duration::from_secs(timeout_seconds));
        let mut handle = self.handle.lock().await;
        let Some(handle) = handle.as_mut() else {
            return Err("SSH access session is closed".into());
        };
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|error| format!("could not open SSH command channel: {error}"))?;
        channel
            .exec(true, command)
            .await
            .map_err(|error| format!("could not start SSH command: {error}"))?;

        let cancelled = self.cancel.clone();
        let result = tokio::select! {
            result = timeout(command_timeout, read_channel(channel)) => {
                match result {
                    Ok(result) => result,
                    Err(_) => Ok((Vec::new(), format!("SSH command timed out after {} seconds\n", command_timeout.as_secs()), 124, true)),
                }
            }
            _ = cancelled.cancelled() => Err("SSH access session was revoked".into()),
        }?;
        let ended_at = Utc::now();
        Ok(SshExecutionResult {
            stdout: String::from_utf8_lossy(&result.0).into_owned(),
            stderr: result.1,
            exit_code: result.2,
            started_at,
            ended_at,
            duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            timed_out: result.3,
        })
    }
}

#[derive(Default)]
pub struct SshSessionRegistry {
    sessions: Mutex<HashMap<String, Arc<ActiveSshSession>>>,
}

impl SshSessionRegistry {
    pub async fn connect(
        &self,
        tool: &ConfiguredTool,
        password: SensitiveString,
    ) -> Result<(), String> {
        if tool.kind != ConfiguredToolKind::SshExec
            || tool.ssh_authentication != SshAuthentication::Password
        {
            return Err("tool is not configured for a password SSH session".into());
        }
        if tool.ssh_host.trim().is_empty() || tool.ssh_user.trim().is_empty() {
            return Err("SSH password sessions require a host and user".into());
        }
        if tool.ssh_host_fingerprint.trim().is_empty() {
            return Err("SSH password sessions require a pinned SHA-256 host fingerprint".into());
        }
        if !(1..=3600).contains(&tool.ssh_session_seconds) {
            return Err("SSH session lifetime must be between 1 and 3600 seconds".into());
        }
        let old = self.sessions.lock().await.remove(&tool.name);
        if let Some(old) = old {
            old.close().await;
        }

        let port = if tool.ssh_port == 0 {
            22
        } else {
            tool.ssh_port
        };
        let config = client::Config {
            inactivity_timeout: Some(Duration::from_secs(tool.ssh_session_seconds)),
            keepalive_interval: Some(KEEPALIVE_INTERVAL),
            keepalive_max: 3,
            ..Default::default()
        };
        let handler = HostKeyChecker {
            fingerprint: tool.ssh_host_fingerprint.trim().to_string(),
        };
        let connect = timeout(
            CONNECT_TIMEOUT,
            client::connect(Arc::new(config), (tool.ssh_host.as_str(), port), handler),
        )
        .await
        .map_err(|_| "SSH connection timed out".to_string())?;
        let mut handle = match connect {
            Ok(handle) => handle,
            Err(error) => {
                return Err(format!("could not connect to SSH server: {error}"));
            }
        };
        let auth = timeout(
            CONNECT_TIMEOUT,
            handle.authenticate_password(tool.ssh_user.clone(), password.as_str()),
        )
        .await;
        let auth = auth.map_err(|_| "SSH authentication timed out".to_string())?;
        let auth = auth.map_err(|error| format!("SSH authentication failed: {error}"))?;
        if !auth.success() {
            let _ = handle
                .disconnect(Disconnect::ByApplication, "authentication failed", "en")
                .await;
            return Err("SSH authentication failed".into());
        }

        let active = Arc::new(ActiveSshSession {
            expires_at: Instant::now() + Duration::from_secs(tool.ssh_session_seconds),
            cancel: CancellationToken::new(),
            handle: Mutex::new(Some(handle)),
        });
        let session_seconds = tool.ssh_session_seconds;
        self.sessions
            .lock()
            .await
            .insert(tool.name.clone(), Arc::clone(&active));
        let expires = Arc::clone(&active);
        tokio::spawn(async move {
            sleep(Duration::from_secs(session_seconds)).await;
            expires.close().await;
        });
        Ok(())
    }

    pub async fn execute(
        &self,
        tool_name: &str,
        command: String,
        timeout_seconds: u64,
    ) -> Result<SshExecutionResult, String> {
        let session = self
            .sessions
            .lock()
            .await
            .get(tool_name)
            .cloned()
            .ok_or_else(|| format!("SSH access is locked for tool {tool_name:?}"))?;
        if session.expires_at <= Instant::now() {
            self.revoke(tool_name).await;
            return Err("SSH access session has expired".into());
        }
        session.execute(command, timeout_seconds).await
    }

    pub async fn revoke(&self, tool_name: &str) {
        if let Some(session) = self.sessions.lock().await.remove(tool_name) {
            session.close().await;
        }
    }

    pub async fn revoke_all(&self) {
        let sessions = std::mem::take(&mut *self.sessions.lock().await);
        for session in sessions.into_values() {
            session.close().await;
        }
    }
}

async fn read_channel(
    mut channel: russh::Channel<russh::client::Msg>,
) -> Result<(Vec<u8>, String, i32, bool), String> {
    let mut stdout = Vec::new();
    let mut stderr = String::new();
    let mut remaining = MAX_OUTPUT_BYTES;
    let mut exit_code = 1;
    while let Some(message) = channel.wait().await {
        match message {
            ChannelMsg::Data { data } => append_bounded(&mut stdout, &data, &mut remaining),
            ChannelMsg::ExtendedData { data, .. } => {
                let keep = data.len().min(remaining);
                stderr.push_str(&String::from_utf8_lossy(&data[..keep]));
                remaining -= keep;
            }
            ChannelMsg::ExitStatus { exit_status } => exit_code = exit_status as i32,
            ChannelMsg::Close => break,
            ChannelMsg::Eof | ChannelMsg::ExitSignal { .. } => {}
            _ => {}
        }
    }
    Ok((stdout, stderr, exit_code, false))
}

fn append_bounded(output: &mut Vec<u8>, data: &[u8], remaining: &mut usize) {
    let keep = data.len().min(*remaining);
    output.extend_from_slice(&data[..keep]);
    *remaining -= keep;
}

pub async fn control_loop(server: McpServer) {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut events = BufWriter::new(tokio::io::stdout());
    loop {
        let mut line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) | Err(_) => break,
        };
        let mut request = serde_json::from_str::<SshControlRequest>(&line);
        match &mut request {
            Ok(SshControlRequest::Connect { tool, password }) => {
                let tool_name = tool.clone();
                let Some(configured) = server
                    .settings
                    .configured_tools
                    .iter()
                    .find(|candidate| candidate.name == tool_name)
                else {
                    tracing::warn!(tool = %tool_name, "SSH control request referenced an unknown tool");
                    send_control_event(
                        &mut events,
                        SshControlEvent::Error {
                            tool: Some(tool_name.clone()),
                            message: "SSH control request referenced an unknown tool".into(),
                        },
                    )
                    .await;
                    line.zeroize();
                    continue;
                };
                let password = std::mem::take(password);
                match server.ssh_sessions.connect(configured, password).await {
                    Ok(()) => {
                        send_control_event(
                            &mut events,
                            SshControlEvent::Connected {
                                tool: tool_name.clone(),
                            },
                        )
                        .await;
                    }
                    Err(error) => {
                        tracing::warn!(tool = %tool_name, "SSH connection request failed: {error}");
                        send_control_event(
                            &mut events,
                            SshControlEvent::Error {
                                tool: Some(tool_name.clone()),
                                message: error,
                            },
                        )
                        .await;
                    }
                }
            }
            Ok(SshControlRequest::Revoke { tool }) => {
                let tool = tool.clone();
                server.ssh_sessions.revoke(&tool).await;
                send_control_event(&mut events, SshControlEvent::Revoked { tool }).await;
            }
            Ok(SshControlRequest::RevokeAll) => {
                server.ssh_sessions.revoke_all().await;
            }
            Err(error) => {
                tracing::warn!("invalid SSH control request: {error}");
                send_control_event(
                    &mut events,
                    SshControlEvent::Error {
                        tool: None,
                        message: format!("invalid SSH control request: {error}"),
                    },
                )
                .await;
            }
        }
        line.zeroize();
    }
    server.ssh_sessions.revoke_all().await;
}

async fn send_control_event(events: &mut BufWriter<tokio::io::Stdout>, event: SshControlEvent) {
    let Ok(mut encoded) = serde_json::to_vec(&event) else {
        return;
    };
    encoded.push(b'\n');
    let _ = events.write_all(&encoded).await;
    let _ = events.flush().await;
    encoded.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_string_redacts_debug_output_and_serializes_only_on_request() {
        let secret = SensitiveString::new("correct horse battery staple");
        let debug = format!("{secret:?}");
        assert!(!debug.contains("correct horse"));
        assert_eq!(
            serde_json::to_string(&secret).unwrap(),
            "\"correct horse battery staple\""
        );
    }

    #[test]
    fn control_request_debug_does_not_include_password() {
        let request = SshControlRequest::Connect {
            tool: "maintenance".into(),
            password: SensitiveString::new("secret-value"),
        };
        assert!(!format!("{request:?}").contains("secret-value"));
    }
}
