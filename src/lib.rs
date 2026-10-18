use std::{
    collections::BTreeSet,
    env, fs,
    path::{Path, PathBuf},
};

#[cfg(test)]
use std::sync::{Mutex, MutexGuard, OnceLock};

use serde::{Deserialize, Serialize};

pub mod commands;
pub mod ssh;

#[cfg(test)]
pub(crate) fn test_environment_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

#[derive(Debug, Clone, Copy)]
pub struct CommandSpec {
    pub name: &'static str,
    pub description: &'static str,
    pub default_enabled: bool,
    pub privileged: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CommandGroup {
    pub name: &'static str,
    pub description: &'static str,
    pub command_names: &'static [&'static str],
}

pub const COMMAND_GROUPS: &[CommandGroup] = &[
    CommandGroup {
        name: "Core",
        description: "Connectivity and basic process inspection.",
        command_names: &["health", "echo", "ps"],
    },
    CommandGroup {
        name: "Files and system",
        description: "Filesystem, journal, kernel, and system information.",
        command_names: &[
            "ls",
            "cat",
            "journalctl",
            "uname",
            "kernel_cmdline",
            "kernel_modules",
            "module_info",
        ],
    },
    CommandGroup {
        name: "Hardware",
        description: "USB, PCI, USB-C, and Thunderbolt inspection.",
        command_names: &[
            "lsusb",
            "usb_topology",
            "lspci",
            "boltctl",
            "pci_device_state",
            "typec_state",
            "thunderbolt_state",
            "usb_authorization_state",
        ],
    },
    CommandGroup {
        name: "Display",
        description: "Display servers, outputs, DRM, and connector state.",
        command_names: &[
            "xrandr",
            "wayland_info",
            "wlr_randr",
            "jay_randr",
            "kscreen_doctor",
            "gnome_display_state",
            "drm_info",
            "modetest",
            "drm_connector_state",
        ],
    },
    CommandGroup {
        name: "Drivers and security",
        description: "Kernel messages, drivers, GPU state, and boot security.",
        command_names: &[
            "dmesg",
            "ubuntu_drivers",
            "nvidia_smi",
            "nvidia_modinfo",
            "nvidia_driver_state",
            "secure_boot_state",
            "dkms_status",
            "nvidia_packages",
            "prime_select",
            "supergfx_mode",
        ],
    },
    CommandGroup {
        name: "Diagnostics",
        description: "Combined hardware and display diagnosis.",
        command_names: &["display_diagnostics"],
    },
];

pub const COMMAND_SPECS: &[CommandSpec] = &[
    CommandSpec {
        name: "health",
        description: "Check that the command service is ready.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "echo",
        description: "Echo a bounded message for connectivity testing.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "ls",
        description: "List a file or directory inside configured read roots.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "cat",
        description: "Read one regular file inside configured read roots.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "ps",
        description: "Search running processes by command line.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "journalctl",
        description: "Read bounded system journal entries.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "lsusb",
        description: "List USB devices.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "usb_topology",
        description: "Show the USB device tree.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "lspci",
        description: "List PCI devices and drivers.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "dmesg",
        description: "Read kernel messages.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "xrandr",
        description: "Show X11/XWayland display state.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "wayland_info",
        description: "Show Wayland globals and output capabilities.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "wlr_randr",
        description: "Show outputs for wlroots compositors.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "jay_randr",
        description: "Show Jay DRM devices and outputs.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "kscreen_doctor",
        description: "Show KDE Plasma output state.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "gnome_display_state",
        description: "Query GNOME Mutter display state.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "drm_info",
        description: "Show DRM devices and connector properties.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "modetest",
        description: "Show kernel DRM connectors and modes.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "boltctl",
        description: "List USB-C and Thunderbolt devices.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "uname",
        description: "Show kernel and system architecture information.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "kernel_cmdline",
        description: "Show kernel boot parameters.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "kernel_modules",
        description: "List loaded kernel modules.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "module_info",
        description: "Show metadata for one kernel module.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "pci_device_state",
        description: "Show sysfs state for one PCI function.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "typec_state",
        description: "Show Linux USB-C class state.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "thunderbolt_state",
        description: "Show USB4 and Thunderbolt state.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "drm_connector_state",
        description: "Show DRM connectors and EDID presence.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "usb_authorization_state",
        description: "Show USB authorization state.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "ubuntu_drivers",
        description: "List Ubuntu driver recommendations.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "nvidia_smi",
        description: "Show NVIDIA GPU and driver state.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "nvidia_modinfo",
        description: "Show NVIDIA kernel module metadata.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "nvidia_driver_state",
        description: "Show NVIDIA module and runtime state.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "secure_boot_state",
        description: "Show UEFI Secure Boot state.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "dkms_status",
        description: "Show DKMS module status.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "nvidia_packages",
        description: "Show installed NVIDIA packages.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "prime_select",
        description: "Show the selected Ubuntu PRIME mode.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "supergfx_mode",
        description: "Show ASUS supergfxctl GPU mode.",
        default_enabled: false,
        privileged: false,
    },
    CommandSpec {
        name: "display_diagnostics",
        description: "Collect a USB-C monitor and GPU diagnosis snapshot.",
        default_enabled: false,
        privileged: false,
    },
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConfiguredToolKind {
    #[default]
    Local,
    SshExec,
    #[doc(hidden)]
    #[serde(rename = "ssh_password")]
    LegacySshPassword,
    ScpUpload,
    Docker,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SshAuthentication {
    #[default]
    Agent,
    IdentityFile,
    Password,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolParameter {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "type", default = "default_parameter_type")]
    pub type_name: String,
    #[serde(default = "default_true")]
    pub required: bool,
}

fn default_parameter_type() -> String {
    "string".into()
}

fn default_true() -> bool {
    true
}

fn default_tool_timeout() -> u64 {
    120
}

fn default_ssh_session_seconds() -> u64 {
    900
}

fn default_server_host() -> String {
    "127.0.0.1".into()
}

fn default_server_port() -> u16 {
    8000
}

fn default_env_file() -> String {
    ".env".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    #[serde(default = "default_server_host")]
    pub host: String,
    #[serde(default = "default_server_port")]
    pub port: u16,
    #[serde(default = "default_true")]
    pub auth_enabled: bool,
    #[serde(default = "default_env_file")]
    pub env_file: String,
    #[serde(default)]
    pub allow_unauthenticated_remote: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_server_host(),
            port: default_server_port(),
            auth_enabled: true,
            env_file: default_env_file(),
            allow_unauthenticated_remote: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfiguredTool {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub kind: ConfiguredToolKind,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub command: String,
    #[serde(default)]
    pub parameters: Vec<ToolParameter>,
    #[serde(default = "default_tool_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub ssh_host: String,
    #[serde(default)]
    pub ssh_user: String,
    #[serde(default)]
    pub ssh_port: u16,
    #[serde(default)]
    pub ssh_identity_file: String,
    #[serde(default)]
    pub ssh_authentication: SshAuthentication,
    #[serde(default)]
    pub ssh_host_fingerprint: String,
    #[serde(default = "default_ssh_session_seconds")]
    pub ssh_session_seconds: u64,
    #[serde(default)]
    pub upload_source: String,
    #[serde(default = "default_destination_parameter")]
    pub upload_destination_parameter: String,
    #[serde(default)]
    pub dockerfile: String,
    #[serde(default)]
    pub docker_context: String,
    #[serde(default)]
    pub docker_env: Vec<String>,
}

impl Default for ConfiguredTool {
    fn default() -> Self {
        Self {
            name: "new_tool".into(),
            description: "A configured command tool.".into(),
            kind: ConfiguredToolKind::Local,
            enabled: false,
            command: "echo {message}".into(),
            parameters: vec![ToolParameter {
                name: "message".into(),
                description: "Message to echo.".into(),
                type_name: "string".into(),
                required: true,
            }],
            timeout_seconds: 120,
            ssh_host: String::new(),
            ssh_user: String::new(),
            ssh_port: 22,
            ssh_identity_file: String::new(),
            ssh_authentication: SshAuthentication::Agent,
            ssh_host_fingerprint: String::new(),
            ssh_session_seconds: default_ssh_session_seconds(),
            upload_source: String::new(),
            upload_destination_parameter: "destination".into(),
            dockerfile: String::new(),
            docker_context: String::new(),
            docker_env: Vec::new(),
        }
    }
}

impl ConfiguredTool {
    pub fn normalize_legacy_ssh_authentication(&mut self) {
        if self.kind == ConfiguredToolKind::LegacySshPassword {
            self.kind = ConfiguredToolKind::SshExec;
            self.ssh_authentication = SshAuthentication::Password;
        }
    }
}

fn default_destination_parameter() -> String {
    "destination".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommandConfig {
    #[serde(default)]
    pub enabled_commands: Option<BTreeSet<String>>,
    #[serde(default)]
    pub tools: Vec<ConfiguredTool>,
    #[serde(default)]
    pub server: ServerConfig,
}

#[derive(Debug, Clone)]
pub struct Settings {
    pub host: String,
    pub port: u16,
    pub api_key: Option<String>,
    pub read_roots: Vec<PathBuf>,
    pub allow_unauthenticated_remote: bool,
    pub allow_sensitive_file_reads: bool,
    pub config_path: PathBuf,
    pub enabled_commands: BTreeSet<String>,
    pub configured_tools: Vec<ConfiguredTool>,
}

pub fn default_enabled_commands() -> BTreeSet<String> {
    COMMAND_SPECS
        .iter()
        .filter(|spec| spec.default_enabled)
        .map(|spec| spec.name.to_string())
        .collect()
}

pub fn app_config_dir() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("COMMAND_MCP_CONFIG_DIR") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(windows)]
    let base = env::var_os("APPDATA")
        .or_else(|| env::var_os("LOCALAPPDATA"))
        .map(PathBuf::from)
        .ok_or_else(|| "APPDATA or LOCALAPPDATA is not set".to_string())?;
    #[cfg(target_os = "macos")]
    let base = env::var_os("HOME")
        .map(PathBuf::from)
        .map(|path| path.join("Library").join("Application Support"))
        .ok_or_else(|| "HOME is not set".to_string())?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|path| PathBuf::from(path).join(".config")))
        .ok_or_else(|| "XDG_CONFIG_HOME or HOME is not set".to_string())?;
    #[cfg(not(any(windows, unix)))]
    let base = env::temp_dir();
    Ok(base.join("command-mcp"))
}

pub fn command_config_path() -> Result<PathBuf, String> {
    env::var_os("COMMAND_MCP_CONFIG")
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(|| app_config_dir().map(|path| path.join("config.toml")))
}

pub fn env_file_path(config: &CommandConfig) -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("COMMAND_MCP_ENV_FILE") {
        return Ok(PathBuf::from(path));
    }
    let path = if config.server.env_file.trim().is_empty() {
        PathBuf::from(".env")
    } else {
        PathBuf::from(config.server.env_file.clone())
    };
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(app_config_dir()?.join(path))
    }
}

pub fn app_data_dir() -> Result<PathBuf, String> {
    if let Some(path) = env::var_os("COMMAND_MCP_DATA_DIR") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(windows)]
    let base = env::var_os("LOCALAPPDATA")
        .or_else(|| env::var_os("APPDATA"))
        .map(PathBuf::from)
        .ok_or_else(|| "LOCALAPPDATA is not set".to_string())?;
    #[cfg(target_os = "macos")]
    let base = env::var_os("HOME")
        .map(PathBuf::from)
        .map(|path| path.join("Library").join("Application Support"))
        .ok_or_else(|| "HOME is not set".to_string())?;
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|path| PathBuf::from(path).join(".local/share")))
        .ok_or_else(|| "XDG_DATA_HOME or HOME is not set".to_string())?;
    #[cfg(not(any(windows, unix)))]
    let base =
        env::current_dir().map_err(|error| format!("find application data directory: {error}"))?;
    Ok(base.join("command-mcp"))
}

pub fn managed_dockerfile_path(tool_name: &str) -> Result<PathBuf, String> {
    let safe_name = tool_name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let safe_name = if safe_name.is_empty() {
        "unnamed_tool"
    } else {
        safe_name.as_str()
    };
    Ok(app_data_dir()?
        .join("dockerfiles")
        .join(safe_name)
        .join("Dockerfile"))
}

pub fn save_dockerfile_content(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    fs::write(path, content).map_err(|error| format!("write {}: {error}", path.display()))?;
    set_private_file_permissions(path)
}

pub fn load_env_file(path: &Path) -> Result<std::collections::BTreeMap<String, String>, String> {
    if !path.exists() {
        return Ok(std::collections::BTreeMap::new());
    }
    let text =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        values.insert(
            key.to_string(),
            value.trim().trim_matches(['"', '\'']).to_string(),
        );
    }
    Ok(values)
}

pub fn save_env_file(
    path: &Path,
    values: &std::collections::BTreeMap<String, String>,
) -> Result<(), String> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let text = values
        .iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect::<String>();
    fs::write(path, text).map_err(|error| format!("write {}: {error}", path.display()))?;
    set_private_file_permissions(path)?;
    Ok(())
}

pub fn ensure_env_api_key(path: &Path) -> Result<String, String> {
    let mut values = load_env_file(path)?;
    if let Some(value) = values
        .get("COMMAND_MCP_API_KEY")
        .filter(|value| !value.is_empty())
    {
        return Ok(value.clone());
    }
    if let Ok(value) = env::var("COMMAND_MCP_API_KEY")
        && !value.is_empty()
    {
        return Ok(value);
    }
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| format!("generate API key: {error}"))?;
    let key = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    values.insert("COMMAND_MCP_API_KEY".into(), key.clone());
    save_env_file(path, &values)?;
    Ok(key)
}

fn set_private_file_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("protect {}: {error}", path.display()))?;
    }
    Ok(())
}

pub fn load_command_config(path: &Path) -> Result<CommandConfig, String> {
    if !path.exists() {
        return Ok(CommandConfig::default());
    }
    let text =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let mut config: CommandConfig =
        toml::from_str(&text).map_err(|error| format!("parse {}: {error}", path.display()))?;
    for tool in &mut config.tools {
        tool.normalize_legacy_ssh_authentication();
    }
    Ok(config)
}

pub fn save_command_config(
    path: &Path,
    enabled_commands: &BTreeSet<String>,
    tools: &[ConfiguredTool],
    server: &ServerConfig,
) -> Result<(), String> {
    let config = CommandConfig {
        enabled_commands: Some(enabled_commands.clone()),
        tools: tools.to_vec(),
        server: server.clone(),
    };
    let text =
        toml::to_string_pretty(&config).map_err(|error| format!("serialize config: {error}"))?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    fs::write(path, text).map_err(|error| format!("write {}: {error}", path.display()))?;
    set_private_file_permissions(path)
}

pub fn load_settings() -> Result<Settings, String> {
    let config_path = command_config_path()?;
    let file_config = load_command_config(&config_path)?;
    let env_path = env_file_path(&file_config)?;
    load_dotenv(&env_path);
    let enabled_commands = file_config
        .enabled_commands
        .unwrap_or_else(default_enabled_commands);
    let configured_tools = file_config.tools;
    let read_roots = if let Ok(value) = env::var("COMMAND_MCP_READ_ROOTS") {
        value
            .split(',')
            .filter(|part| !part.trim().is_empty())
            .map(|part| {
                PathBuf::from(part.trim())
                    .canonicalize()
                    .unwrap_or_else(|_| PathBuf::from(part.trim()))
            })
            .collect()
    } else {
        vec![env::current_dir().map_err(|error| error.to_string())?]
    };
    if read_roots.is_empty() {
        return Err("COMMAND_MCP_READ_ROOTS must contain at least one path".to_string());
    }
    let host = env::var("COMMAND_MCP_HOST").unwrap_or_else(|_| file_config.server.host.clone());
    let auth_enabled = env_bool("COMMAND_MCP_AUTH_ENABLED", file_config.server.auth_enabled);
    let mut api_key = env::var("COMMAND_MCP_API_KEY")
        .ok()
        .filter(|value| !value.is_empty());
    if auth_enabled && api_key.is_none() {
        api_key = Some(ensure_env_api_key(&env_path)?);
        // SAFETY: settings are loaded before the server starts worker tasks.
        unsafe {
            env::set_var(
                "COMMAND_MCP_API_KEY",
                api_key.as_deref().unwrap_or_default(),
            );
        }
    }
    if !auth_enabled {
        api_key = None;
    }
    let allow_unauthenticated_remote = env_bool(
        "COMMAND_MCP_ALLOW_UNAUTHENTICATED_REMOTE",
        file_config.server.allow_unauthenticated_remote,
    );
    if !matches!(host.as_str(), "127.0.0.1" | "::1" | "localhost")
        && api_key.is_none()
        && !allow_unauthenticated_remote
    {
        return Err("COMMAND_MCP_API_KEY is required for a non-loopback bind; set COMMAND_MCP_ALLOW_UNAUTHENTICATED_REMOTE=true only for an isolated trusted network".to_string());
    }
    let port = env::var("COMMAND_MCP_PORT")
        .unwrap_or_else(|_| file_config.server.port.to_string())
        .parse::<u16>()
        .map_err(|error| format!("invalid COMMAND_MCP_PORT: {error}"))?;
    Ok(Settings {
        host,
        port,
        api_key,
        read_roots,
        allow_unauthenticated_remote,
        allow_sensitive_file_reads: env_bool("COMMAND_MCP_ALLOW_SENSITIVE_FILE_READS", false),
        config_path,
        enabled_commands,
        configured_tools,
    })
}

fn env_bool(name: &str, default: bool) -> bool {
    match env::var(name).ok().as_deref() {
        Some(value)
            if matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            ) =>
        {
            true
        }
        Some(value)
            if matches!(
                value.to_ascii_lowercase().as_str(),
                "0" | "false" | "no" | "off"
            ) =>
        {
            false
        }
        _ => default,
    }
}

fn load_dotenv(path: &Path) {
    let Ok(text) = fs::read_to_string(path) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if env::var_os(key.trim()).is_none() {
            let value = value.trim().trim_matches(['"', '\'']);
            // SAFETY: dotenv loading happens before Tokio starts worker threads.
            unsafe {
                env::set_var(key.trim(), value);
            }
        }
    }
}

pub fn spec(name: &str) -> Option<&'static CommandSpec> {
    COMMAND_SPECS.iter().find(|spec| spec.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_api_key_is_generated_and_saved() {
        let _environment_lock = test_environment_lock();
        let path = env::temp_dir().join(format!(
            "command-mcp-test-{}-api-key.env",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let key = ensure_env_api_key(&path).expect("generate API key");
        assert_eq!(key.len(), 64);
        assert_eq!(load_env_file(&path).unwrap()["COMMAND_MCP_API_KEY"], key);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn managed_dockerfile_is_saved_under_application_data() {
        let _environment_lock = test_environment_lock();
        let data_dir = env::temp_dir().join(format!(
            "command-mcp-test-{}-docker-data",
            std::process::id()
        ));
        let previous = env::var_os("COMMAND_MCP_DATA_DIR");
        unsafe { env::set_var("COMMAND_MCP_DATA_DIR", &data_dir) };

        let path = managed_dockerfile_path("build-tool").unwrap();
        save_dockerfile_content(&path, "FROM alpine:3.20\n").unwrap();

        assert!(path.starts_with(&data_dir));
        assert_eq!(fs::read_to_string(&path).unwrap(), "FROM alpine:3.20\n");
        unsafe {
            match previous {
                Some(value) => env::set_var("COMMAND_MCP_DATA_DIR", value),
                None => env::remove_var("COMMAND_MCP_DATA_DIR"),
            }
        }
        let _ = fs::remove_dir_all(data_dir);
    }

    #[test]
    fn configuration_defaults_to_application_directory() {
        let _environment_lock = test_environment_lock();
        let config_dir = env::temp_dir().join(format!(
            "command-mcp-test-{}-config-dir",
            std::process::id()
        ));
        let previous_dir = env::var_os("COMMAND_MCP_CONFIG_DIR");
        let previous_config = env::var_os("COMMAND_MCP_CONFIG");
        let previous_env = env::var_os("COMMAND_MCP_ENV_FILE");
        unsafe {
            env::set_var("COMMAND_MCP_CONFIG_DIR", &config_dir);
            env::remove_var("COMMAND_MCP_CONFIG");
            env::remove_var("COMMAND_MCP_ENV_FILE");
        }

        assert_eq!(
            command_config_path().unwrap(),
            config_dir.join("config.toml")
        );
        assert_eq!(
            env_file_path(&CommandConfig::default()).unwrap(),
            config_dir.join(".env")
        );

        unsafe {
            match previous_dir {
                Some(value) => env::set_var("COMMAND_MCP_CONFIG_DIR", value),
                None => env::remove_var("COMMAND_MCP_CONFIG_DIR"),
            }
            match previous_config {
                Some(value) => env::set_var("COMMAND_MCP_CONFIG", value),
                None => env::remove_var("COMMAND_MCP_CONFIG"),
            }
            match previous_env {
                Some(value) => env::set_var("COMMAND_MCP_ENV_FILE", value),
                None => env::remove_var("COMMAND_MCP_ENV_FILE"),
            }
        }
    }

    #[test]
    fn legacy_password_ssh_tools_are_migrated_to_ssh_authentication() {
        let path = env::temp_dir().join(format!(
            "command-mcp-test-{}-legacy-ssh.toml",
            std::process::id()
        ));
        fs::write(
            &path,
            r#"
                [[tools]]
                name = "maintenance"
                kind = "ssh_password"
                command = "uname -a"
            "#,
        )
        .unwrap();

        let config = load_command_config(&path).unwrap();
        assert_eq!(config.tools[0].kind, ConfiguredToolKind::SshExec);
        assert_eq!(
            config.tools[0].ssh_authentication,
            SshAuthentication::Password
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn command_groups_cover_each_builtin_once() {
        let mut grouped = BTreeSet::new();
        for group in COMMAND_GROUPS {
            assert!(
                !group.command_names.is_empty(),
                "empty group: {}",
                group.name
            );
            for name in group.command_names {
                assert!(spec(name).is_some(), "unknown command in group: {name}");
                assert!(
                    grouped.insert(*name),
                    "command appears in multiple groups: {name}"
                );
            }
        }
        assert_eq!(grouped.len(), COMMAND_SPECS.len());
    }

    #[test]
    fn server_and_tool_configuration_round_trip() {
        let path = env::temp_dir().join(format!(
            "command-mcp-test-{}-config.toml",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        let tool = ConfiguredTool {
            name: "say_message".into(),
            enabled: true,
            command: "echo {message}".into(),
            parameters: vec![ToolParameter {
                name: "message".into(),
                description: "Text to print.".into(),
                type_name: "string".into(),
                required: true,
            }],
            ..ConfiguredTool::default()
        };
        let server = ServerConfig {
            host: "172.17.0.1".into(),
            port: 8123,
            auth_enabled: true,
            env_file: ".test.env".into(),
            allow_unauthenticated_remote: false,
        };

        save_command_config(
            &path,
            &BTreeSet::from(["health".into()]),
            std::slice::from_ref(&tool),
            &server,
        )
        .unwrap();
        let loaded = load_command_config(&path).unwrap();

        assert_eq!(loaded.server, server);
        assert_eq!(
            loaded.enabled_commands,
            Some(BTreeSet::from(["health".into()]))
        );
        assert_eq!(loaded.tools, vec![tool]);
        let _ = fs::remove_file(path);
    }
}
