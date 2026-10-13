use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, HashMap},
    env,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use regex::Regex;
use rmcp::{
    ErrorData as McpError, ServerHandler, ServiceExt,
    handler::server::{
        router::tool::{ToolRoute, ToolRouter},
        wrapper::{Json, Parameters},
    },
    model::{CallToolResponse, CallToolResult, ContentBlock, JsonObject, Tool, ToolAnnotations},
    schemars::JsonSchema,
    tool, tool_handler, tool_router,
    transport::{
        stdio,
        streamable_http_server::{
            StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
        },
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::{io::AsyncRead, process::Command, sync::Mutex, time::timeout};

use crate::{COMMAND_SPECS, ConfiguredTool, ConfiguredToolKind, Settings, spec};

pub const MAX_OUTPUT_BYTES: usize = 200_000;

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub duration_ms: u64,
    pub host: String,
    pub mode: String,
    pub mutating: bool,
    pub timed_out: bool,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub redaction_count: usize,
    pub redactions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct HealthResult {
    pub status: String,
    pub server_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DiagnosticFinding {
    pub severity: String,
    pub code: String,
    pub summary: String,
    pub evidence: Vec<String>,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct DisplayDiagnostics {
    pub system: CommandResult,
    pub kernel_cmdline: CommandResult,
    pub usb_topology: CommandResult,
    pub pci_drivers: CommandResult,
    pub kernel_modules: CommandResult,
    pub typec: BTreeMap<String, BTreeMap<String, String>>,
    pub thunderbolt: BTreeMap<String, BTreeMap<String, String>>,
    pub drm_connectors: BTreeMap<String, BTreeMap<String, String>>,
    pub usb_authorization: BTreeMap<String, BTreeMap<String, String>>,
    pub nvidia_driver_state: BTreeMap<String, BTreeMap<String, String>>,
    pub drm: CommandResult,
    pub nvidia: CommandResult,
    pub nvidia_module: CommandResult,
    pub nvidia_packages: CommandResult,
    pub dkms: CommandResult,
    pub secure_boot: CommandResult,
    pub prime_mode: CommandResult,
    pub asus_gpu_mode: CommandResult,
    pub kernel_events: CommandResult,
    pub assessment: Vec<DiagnosticFinding>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EchoArgs {
    #[schemars(length(min = 1, max = 4096))]
    pub message: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PathArgs {
    #[schemars(length(min = 1, max = 4096))]
    pub filename: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ProcessArgs {
    #[schemars(length(min = 1, max = 200))]
    pub query: String,
    #[serde(default = "default_process_limit")]
    pub limit: u32,
}

fn default_process_limit() -> u32 {
    100
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CloudArgs {
    #[schemars(length(min = 1, max = 4096))]
    pub command: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct JournalArgs {
    #[serde(default = "default_journal_lines")]
    pub lines: u32,
    #[serde(default = "default_true")]
    pub current_boot: bool,
    #[serde(default)]
    pub kernel_only: bool,
    pub priority: Option<String>,
    pub unit: Option<String>,
    pub since: Option<String>,
    pub grep: Option<String>,
}

fn default_journal_lines() -> u32 {
    500
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LsusbArgs {
    #[serde(default)]
    pub verbose: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct LspciArgs {
    #[serde(default)]
    pub verbose: bool,
    #[serde(default)]
    pub numeric: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DmesgArgs {
    pub level: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ModuleArgs {
    #[schemars(length(min = 1, max = 100))]
    pub module: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PciArgs {
    #[schemars(length(min = 7, max = 12))]
    pub address: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct KmodeArgs {
    #[schemars(length(min = 1, max = 16384))]
    pub command: String,
}

#[derive(Clone)]
pub struct McpServer {
    pub settings: Settings,
    pub tool_router: ToolRouter<Self>,
}

impl McpServer {
    pub fn new(settings: Settings) -> anyhow::Result<Self> {
        let mut tool_router = Self::tool_router();
        for spec in COMMAND_SPECS {
            if !settings.enabled_commands.contains(spec.name) {
                tool_router.disable_route(spec.name);
            }
        }
        let mut names = BTreeSet::new();
        for configured_tool in &settings.configured_tools {
            validate_configured_tool(configured_tool, &mut names)?;
            let route = configured_tool_route(configured_tool.clone());
            let name = configured_tool.name.clone();
            tool_router.add_route(route);
            if !configured_tool.enabled {
                tool_router.disable_route(name);
            }
        }
        Ok(Self {
            settings,
            tool_router,
        })
    }

    fn error(message: impl Into<String>) -> McpError {
        McpError::invalid_params(message.into(), None)
    }

    fn approved_path(&self, filename: &str, require_file: bool) -> Result<PathBuf, McpError> {
        let target = PathBuf::from(filename)
            .canonicalize()
            .map_err(|error| Self::error(format!("cannot resolve path: {error}")))?;
        let approved = self
            .settings
            .read_roots
            .iter()
            .any(|root| target == *root || target.starts_with(root));
        if !approved {
            return Err(Self::error("path is outside COMMAND_MCP_READ_ROOTS"));
        }
        if !self.settings.allow_sensitive_file_reads && is_sensitive_path(&target) {
            return Err(Self::error("sensitive credential paths are blocked"));
        }
        if require_file && !target.is_file() {
            return Err(Self::error("path is not a regular file"));
        }
        Ok(target)
    }
}

#[tool_router]
impl McpServer {
    #[tool(description = "Check that the command service is ready.")]
    async fn health(&self) -> Json<HealthResult> {
        Json(HealthResult {
            status: "ok".to_string(),
            server_time: Utc::now(),
        })
    }

    #[tool(description = "Echo a bounded message. Useful for testing MCP connectivity.")]
    async fn echo(&self, Parameters(args): Parameters<EchoArgs>) -> Result<Json<Value>, McpError> {
        if args.message.is_empty() || args.message.len() > 4096 {
            return Err(Self::error("message must contain 1 to 4096 characters"));
        }
        Ok(Json(json!({"message": args.message})))
    }

    #[tool(description = "List one file or directory inside the configured read roots.")]
    async fn ls(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<Json<CommandResult>, McpError> {
        let path = self.approved_path(&args.filename, false)?;
        Ok(Json(
            run_read_only(
                vec!["ls".into(), "--".into(), path.display().to_string()],
                15,
                None,
                false,
            )
            .await,
        ))
    }

    #[tool(description = "Read one regular file inside the configured read roots.")]
    async fn cat(
        &self,
        Parameters(args): Parameters<PathArgs>,
    ) -> Result<Json<CommandResult>, McpError> {
        let path = self.approved_path(&args.filename, true)?;
        Ok(Json(
            run_read_only(
                vec!["cat".into(), "--".into(), path.display().to_string()],
                15,
                None,
                false,
            )
            .await,
        ))
    }

    #[tool(
        name = "ps",
        description = "Search running processes by command line, case-insensitively."
    )]
    async fn search_processes(
        &self,
        Parameters(args): Parameters<ProcessArgs>,
    ) -> Result<Json<CommandResult>, McpError> {
        if args.query.is_empty() || args.query.len() > 200 || !(1..=1000).contains(&args.limit) {
            return Err(Self::error(
                "query must be 1-200 characters and limit must be 1-1000",
            ));
        }
        let mut result = run_read_only(
            vec!["ps", "-ww", "-eo", "pid=,ppid=,user=,stat=,lstart=,args="]
                .into_iter()
                .map(String::from)
                .collect(),
            15,
            None,
            false,
        )
        .await;
        if result.exit_code == 0 {
            let query = args.query.to_ascii_lowercase();
            let mut matches: Vec<&str> = result
                .stdout
                .lines()
                .filter(|line| line.to_ascii_lowercase().contains(&query))
                .collect();
            let truncated = matches.len() > args.limit as usize;
            matches.truncate(args.limit as usize);
            result.stdout = matches.join("\n");
            if !result.stdout.is_empty() {
                result.stdout.push('\n');
            }
            if truncated {
                result.stdout.push_str(&format!(
                    "[results truncated to {} processes]\n",
                    args.limit
                ));
            }
        }
        Ok(Json(result))
    }

    #[tool(description = "Execute an allowlisted read-only gcloud command without a shell.")]
    async fn gcloud(
        &self,
        Parameters(args): Parameters<CloudArgs>,
    ) -> Result<Json<CommandResult>, McpError> {
        Ok(Json(
            run_cloud_command(
                &args.command,
                "gcloud",
                &[
                    &["auth", "list"],
                    &["compute", "instances", "describe"],
                    &["compute", "instances", "list"],
                    &["config", "get-value"],
                    &["projects", "describe"],
                    &["projects", "list"],
                ],
            )
            .await,
        ))
    }

    #[tool(description = "Execute an allowlisted read-only AWS command without a shell.")]
    async fn aws(
        &self,
        Parameters(args): Parameters<CloudArgs>,
    ) -> Result<Json<CommandResult>, McpError> {
        Ok(Json(
            run_cloud_command(
                &args.command,
                "aws",
                &[
                    &["ec2", "describe-instances"],
                    &["ec2", "describe-regions"],
                    &["ec2", "describe-security-groups"],
                    &["ec2", "describe-subnets"],
                    &["ec2", "describe-vpcs"],
                    &["iam", "get-account-summary"],
                    &["iam", "list-roles"],
                    &["iam", "list-users"],
                    &["pricing", "describe-services"],
                    &["pricing", "get-attribute-values"],
                    &["pricing", "get-products"],
                    &["s3api", "get-bucket-location"],
                    &["s3api", "list-buckets"],
                    &["s3api", "list-objects-v2"],
                    &["sts", "get-caller-identity"],
                ],
            )
            .await,
        ))
    }

    #[tool(description = "Read bounded system journal entries using common diagnostic filters.")]
    async fn journalctl(
        &self,
        Parameters(args): Parameters<JournalArgs>,
    ) -> Result<Json<CommandResult>, McpError> {
        if !(1..=5000).contains(&args.lines) {
            return Err(Self::error("lines must be between 1 and 5000"));
        }
        let mut argv = vec![
            "journalctl".into(),
            "--no-pager".into(),
            "--output=short-iso".into(),
            format!("--lines={}", args.lines),
        ];
        if args.current_boot {
            argv.push("--boot=0".into());
        }
        if args.kernel_only {
            argv.push("--dmesg".into());
        }
        if let Some(priority) = bounded_arg(args.priority, 20, "priority")? {
            argv.push(format!("--priority={priority}"));
        }
        if let Some(unit) = bounded_arg(args.unit, 200, "unit")? {
            argv.extend(["--unit".into(), unit]);
        }
        if let Some(since) = bounded_arg(args.since, 100, "since")? {
            argv.extend(["--since".into(), since]);
        }
        if let Some(grep) = bounded_arg(args.grep, 200, "grep")? {
            argv.extend(["--grep".into(), grep]);
        }
        Ok(Json(run_read_only(argv, 30, None, false).await))
    }

    #[tool(description = "List USB devices; verbose mode includes descriptors.")]
    async fn lsusb(&self, Parameters(args): Parameters<LsusbArgs>) -> Json<CommandResult> {
        let mut argv = vec!["lsusb".into()];
        if args.verbose {
            argv.push("--verbose".into());
        }
        Json(run_read_only(argv, 30, None, false).await)
    }

    #[tool(description = "Show the USB device tree, negotiated speeds, ports, and bound drivers.")]
    async fn usb_topology(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["lsusb".into(), "--tree".into()], 15, None, false).await)
    }

    #[tool(description = "List PCI devices and their drivers.")]
    async fn lspci(&self, Parameters(args): Parameters<LspciArgs>) -> Json<CommandResult> {
        let mut argv = vec!["lspci".into(), "-k".into()];
        if args.verbose {
            argv.push("-vv".into());
        }
        if args.numeric {
            argv.push("-nn".into());
        }
        Json(run_read_only(argv, 30, None, false).await)
    }

    #[tool(description = "Read kernel messages, optionally restricted to a severity level.")]
    async fn dmesg(
        &self,
        Parameters(args): Parameters<DmesgArgs>,
    ) -> Result<Json<CommandResult>, McpError> {
        let mut argv = vec!["dmesg".into(), "--color=never".into()];
        if let Some(level) = bounded_arg(args.level, 20, "level")? {
            argv.push(format!("--level={level}"));
        }
        Ok(Json(run_read_only(argv, 15, None, false).await))
    }

    #[tool(description = "Show X11/XWayland display state; on Wayland this may be incomplete.")]
    async fn xrandr(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["xrandr".into(), "--query".into()], 15, None, false).await)
    }

    #[tool(description = "Show Wayland globals and output capabilities for the active session.")]
    async fn wayland_info(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["wayland-info".into()], 30, None, false).await)
    }

    #[tool(description = "Show outputs for wlroots-based Wayland compositors.")]
    async fn wlr_randr(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["wlr-randr".into()], 15, None, false).await)
    }

    #[tool(description = "Show Jay's DRM devices, connectors, outputs, and modes as JSON.")]
    async fn jay_randr(&self) -> Json<CommandResult> {
        Json(
            run_read_only(
                vec!["jay".into(), "--json".into(), "randr".into()],
                30,
                None,
                false,
            )
            .await,
        )
    }

    #[tool(description = "Show output state under KDE Plasma Wayland.")]
    async fn kscreen_doctor(&self) -> Json<CommandResult> {
        Json(
            run_read_only(
                vec!["kscreen-doctor".into(), "--outputs".into()],
                15,
                None,
                false,
            )
            .await,
        )
    }

    #[tool(
        description = "Query GNOME Mutter for its current monitors, modes, and logical displays."
    )]
    async fn gnome_display_state(&self) -> Json<CommandResult> {
        Json(
            run_read_only(
                vec![
                    "gdbus",
                    "call",
                    "--session",
                    "--dest",
                    "org.gnome.Mutter.DisplayConfig",
                    "--object-path",
                    "/org/gnome/Mutter/DisplayConfig",
                    "--method",
                    "org.gnome.Mutter.DisplayConfig.GetCurrentState",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
                30,
                None,
                false,
            )
            .await,
        )
    }

    #[tool(description = "Show DRM devices, connectors, properties, and supported modes.")]
    async fn drm_info(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["drm_info".into()], 30, None, false).await)
    }

    #[tool(description = "Show kernel DRM connectors, encoders, CRTCs, and modes.")]
    async fn modetest(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["modetest".into(), "-c".into()], 30, None, false).await)
    }

    #[tool(description = "List known USB-C/Thunderbolt devices and authorization state.")]
    async fn boltctl(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["boltctl".into(), "list".into()], 15, None, false).await)
    }

    #[tool(description = "Show kernel and system architecture information.")]
    async fn uname(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["uname".into(), "-a".into()], 15, None, false).await)
    }

    #[tool(description = "Show kernel boot parameters that may alter graphics drivers.")]
    async fn kernel_cmdline(&self) -> Json<CommandResult> {
        Json(
            run_read_only(
                vec!["cat".into(), "--".into(), "/proc/cmdline".into()],
                15,
                None,
                false,
            )
            .await,
        )
    }

    #[tool(description = "List loaded kernel modules, including graphics and Type-C drivers.")]
    async fn kernel_modules(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["lsmod".into()], 15, None, false).await)
    }

    #[tool(description = "Show metadata for one safely validated kernel-module name.")]
    async fn module_info(
        &self,
        Parameters(args): Parameters<ModuleArgs>,
    ) -> Result<Json<CommandResult>, McpError> {
        let valid = Regex::new(r"^[A-Za-z0-9_+\-]{1,100}$").unwrap();
        if !valid.is_match(&args.module) {
            return Err(Self::error(
                "module must contain only letters, digits, _, +, or -",
            ));
        }
        Ok(Json(
            run_read_only(
                vec!["modinfo".into(), "--".into(), args.module],
                15,
                None,
                false,
            )
            .await,
        ))
    }

    #[tool(
        description = "Show sysfs driver, power, class, vendor, and device state for one PCI function."
    )]
    async fn pci_device_state(
        &self,
        Parameters(args): Parameters<PciArgs>,
    ) -> Result<Json<BTreeMap<String, String>>, McpError> {
        let re = Regex::new(r"^(?:(?P<domain>[0-9A-Fa-f]{4}):)?(?P<bus>[0-9A-Fa-f]{2}):(?P<slot>[0-9A-Fa-f]{2})\.(?P<function>[0-7])$").unwrap();
        let Some(caps) = re.captures(&args.address) else {
            return Err(Self::error(
                "address must look like 01:00.0 or 0000:01:00.0",
            ));
        };
        let canonical = format!(
            "{}:{}:{}.{}",
            caps.name("domain").map(|m| m.as_str()).unwrap_or("0000"),
            &caps["bus"],
            &caps["slot"],
            &caps["function"]
        )
        .to_ascii_lowercase();
        let entry = PathBuf::from("/sys/bus/pci/devices").join(&canonical);
        if !entry.is_dir() {
            return Err(Self::error(format!(
                "PCI device {canonical} does not exist"
            )));
        }
        let mut values = read_attributes(
            &entry,
            &[
                "vendor",
                "device",
                "subsystem_vendor",
                "subsystem_device",
                "class",
                "enable",
                "power_state",
                "power/control",
                "power/runtime_status",
                "power/runtime_suspended_time",
            ],
        );
        if let Ok(driver) = entry.join("driver").canonicalize() {
            values.insert(
                "driver".into(),
                driver
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into(),
            );
        }
        values.insert("address".into(), canonical);
        Ok(Json(values))
    }

    #[tool(
        description = "Show Linux USB-C ports, partners, cable identities, roles, and Alt Modes."
    )]
    async fn typec_state(&self) -> Json<BTreeMap<String, BTreeMap<String, String>>> {
        Json(sysfs_collection(
            Path::new("/sys/class/typec"),
            &[
                "data_role",
                "power_role",
                "port_type",
                "power_operation_mode",
                "preferred_role",
                "accessory_mode",
                "active",
                "mode",
                "svid",
                "vdo",
                "usb_power_delivery_revision",
            ],
            None,
        ))
    }

    #[tool(
        description = "Show USB4/Thunderbolt domains, routers, ports, authorization, and link state."
    )]
    async fn thunderbolt_state(&self) -> Json<BTreeMap<String, BTreeMap<String, String>>> {
        Json(sysfs_collection(
            Path::new("/sys/bus/thunderbolt/devices"),
            &[
                "authorized",
                "device",
                "device_name",
                "vendor",
                "vendor_name",
                "unique_id",
                "generation",
                "security",
                "iommu_dma_protection",
                "link",
                "offline",
                "nvm_version",
            ],
            None,
        ))
    }

    #[tool(
        description = "Show DRM connectors using sysfs, including owning GPU driver and EDID presence."
    )]
    async fn drm_connector_state(&self) -> Json<BTreeMap<String, BTreeMap<String, String>>> {
        Json(drm_connectors())
    }

    #[tool(
        description = "Show USB root-hub authorization policy and per-device authorization state."
    )]
    async fn usb_authorization_state(&self) -> Json<BTreeMap<String, BTreeMap<String, String>>> {
        Json(sysfs_collection(
            Path::new("/sys/bus/usb/devices"),
            &[
                "authorized",
                "authorized_default",
                "interface_authorized_default",
                "busnum",
                "devnum",
                "speed",
                "idVendor",
                "idProduct",
                "manufacturer",
                "product",
            ],
            None,
        ))
    }

    #[tool(description = "List Ubuntu-detected hardware and recommended driver packages.")]
    async fn ubuntu_drivers(&self) -> Json<CommandResult> {
        Json(
            run_read_only(
                vec!["ubuntu-drivers".into(), "devices".into()],
                30,
                None,
                false,
            )
            .await,
        )
    }

    #[tool(description = "Show detailed NVIDIA GPU, driver, display, and PCI state.")]
    async fn nvidia_smi(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["nvidia-smi".into(), "-q".into()], 30, None, false).await)
    }

    #[tool(description = "Show metadata and parameters for the installed NVIDIA kernel module.")]
    async fn nvidia_modinfo(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["modinfo".into(), "nvidia".into()], 15, None, false).await)
    }

    #[tool(
        description = "Show NVIDIA/nouveau module, DRM KMS, procfs GPU, and runtime-power state."
    )]
    async fn nvidia_driver_state(&self) -> Json<BTreeMap<String, BTreeMap<String, String>>> {
        Json(nvidia_state())
    }

    #[tool(description = "Show whether UEFI Secure Boot is enabled.")]
    async fn secure_boot_state(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["mokutil".into(), "--sb-state".into()], 15, None, false).await)
    }

    #[tool(description = "Show out-of-tree kernel modules and whether they built for this kernel.")]
    async fn dkms_status(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["dkms".into(), "status".into()], 15, None, false).await)
    }

    #[tool(description = "Show installed NVIDIA packages and versions on Debian/Ubuntu systems.")]
    async fn nvidia_packages(&self) -> Json<CommandResult> {
        Json(
            run_read_only(
                vec![
                    "dpkg-query",
                    "--show",
                    "--showformat=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n",
                    "nvidia-*",
                    "libnvidia-*",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
                15,
                None,
                false,
            )
            .await,
        )
    }

    #[tool(description = "Show the Ubuntu PRIME graphics mode selected for the next/current boot.")]
    async fn prime_select(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["prime-select".into(), "query".into()], 15, None, false).await)
    }

    #[tool(description = "Show the active ASUS supergfxctl GPU mode, when supported.")]
    async fn supergfx_mode(&self) -> Json<CommandResult> {
        Json(run_read_only(vec!["supergfxctl".into(), "--get".into()], 15, None, false).await)
    }

    #[tool(description = "Collect a one-call snapshot for USB-C monitor and GPU-driver diagnosis.")]
    async fn display_diagnostics(&self) -> Json<DisplayDiagnostics> {
        let pci = self
            .lspci(Parameters(LspciArgs {
                verbose: false,
                numeric: true,
            }))
            .await;
        let modules = self.kernel_modules().await;
        let typec = self.typec_state().await.0;
        let connectors = self.drm_connector_state().await.0;
        let nvidia = self.nvidia_smi().await;
        let nvidia_module = self.nvidia_modinfo().await;
        let kernel_events = match self
            .journalctl(Parameters(JournalArgs {
                lines: 500,
                current_boot: true,
                kernel_only: true,
                priority: Some("info".into()),
                unit: None,
                since: None,
                grep: Some(
                    "usb|typec|ucsi|thunderbolt|displayport|drm|amdgpu|nvidia|nouveau|NVRM".into(),
                ),
            }))
            .await
        {
            Ok(result) => result.0,
            Err(_) => run_read_only(vec!["journalctl".into()], 30, None, false).await,
        };
        Json(DisplayDiagnostics {
            system: self.uname().await.0,
            kernel_cmdline: self.kernel_cmdline().await.0,
            usb_topology: self.usb_topology().await.0,
            pci_drivers: pci.0.clone(),
            kernel_modules: modules.0.clone(),
            typec: typec.clone(),
            thunderbolt: self.thunderbolt_state().await.0,
            drm_connectors: connectors.clone(),
            usb_authorization: self.usb_authorization_state().await.0,
            nvidia_driver_state: self.nvidia_driver_state().await.0,
            drm: self.drm_info().await.0,
            nvidia: nvidia.0.clone(),
            nvidia_module: nvidia_module.0.clone(),
            nvidia_packages: self.nvidia_packages().await.0,
            dkms: self.dkms_status().await.0,
            secure_boot: self.secure_boot_state().await.0,
            prime_mode: self.prime_select().await.0,
            asus_gpu_mode: self.supergfx_mode().await.0,
            kernel_events,
            assessment: assess_display(
                &pci.0,
                &modules.0,
                &typec,
                &connectors,
                &nvidia.0,
                &nvidia_module.0,
            ),
        })
    }

    #[tool(description = "Execute an unrestricted command through the kmode-root SSH host alias.")]
    async fn kmode_root(&self, Parameters(args): Parameters<KmodeArgs>) -> Json<CommandResult> {
        let mut result = run_read_only(
            vec!["ssh".into(), "kmode-root".into(), args.command],
            120,
            None,
            true,
        )
        .await;
        result.host = "kmode-root".into();
        result.mode = "execute".into();
        result.mutating = true;
        Json(result)
    }
}

fn validate_configured_tool(
    tool: &ConfiguredTool,
    names: &mut BTreeSet<String>,
) -> anyhow::Result<()> {
    let name_re = Regex::new(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")?;
    if !name_re.is_match(&tool.name) {
        anyhow::bail!(
            "configured tool name {:?} must start with a letter and contain only letters, digits, _ or -",
            tool.name
        );
    }
    if spec(&tool.name).is_some() {
        anyhow::bail!(
            "configured tool name {:?} conflicts with a built-in tool",
            tool.name
        );
    }
    if !names.insert(tool.name.clone()) {
        anyhow::bail!("configured tool name {:?} is duplicated", tool.name);
    }
    if !(1..=3600).contains(&tool.timeout_seconds) {
        anyhow::bail!(
            "configured tool {:?} timeout must be between 1 and 3600 seconds",
            tool.name
        );
    }
    let parameter_re = Regex::new(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")?;
    let mut parameters = BTreeSet::new();
    for parameter in &tool.parameters {
        if !parameter_re.is_match(&parameter.name) {
            anyhow::bail!(
                "parameter {:?} in tool {:?} has an invalid name",
                parameter.name,
                tool.name
            );
        }
        if !parameters.insert(parameter.name.clone()) {
            anyhow::bail!(
                "parameter {:?} in tool {:?} is duplicated",
                parameter.name,
                tool.name
            );
        }
        if !matches!(
            parameter.type_name.as_str(),
            "string" | "integer" | "number" | "boolean"
        ) {
            anyhow::bail!(
                "parameter {:?} in tool {:?} must use string, integer, number, or boolean",
                parameter.name,
                tool.name
            );
        }
    }
    if tool.enabled {
        match tool.kind {
            ConfiguredToolKind::Local
            | ConfiguredToolKind::SshExec
            | ConfiguredToolKind::Docker
                if tool.command.trim().is_empty() =>
            {
                anyhow::bail!("configured tool {:?} needs a command", tool.name);
            }
            ConfiguredToolKind::SshExec => {
                if tool.ssh_host.trim().is_empty() {
                    anyhow::bail!("SSH tool {:?} needs an SSH host", tool.name);
                }
            }
            ConfiguredToolKind::ScpUpload => {
                if tool.ssh_host.trim().is_empty() {
                    anyhow::bail!("SCP tool {:?} needs an SSH host", tool.name);
                }
                if tool.upload_source.trim().is_empty() {
                    anyhow::bail!("SCP tool {:?} needs a local source file", tool.name);
                }
                if !parameters.contains(&tool.upload_destination_parameter) {
                    anyhow::bail!(
                        "SCP tool {:?} destination parameter {:?} is not configured",
                        tool.name,
                        tool.upload_destination_parameter
                    );
                }
            }
            ConfiguredToolKind::Docker => {
                if tool.dockerfile.trim().is_empty() || tool.docker_context.trim().is_empty() {
                    anyhow::bail!(
                        "Docker tool {:?} needs both a Dockerfile and build context",
                        tool.name
                    );
                }
            }
            ConfiguredToolKind::Local => {}
        }
    }
    let env_key_re = Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$")?;
    for env_key in &tool.docker_env {
        if !env_key_re.is_match(env_key) {
            anyhow::bail!(
                "Docker tool {:?} has invalid environment variable name {:?}",
                tool.name,
                env_key
            );
        }
    }
    Ok(())
}

fn configured_tool_schema(tool: &ConfiguredTool) -> Tool {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for parameter in &tool.parameters {
        properties.insert(
            parameter.name.clone(),
            json!({
                "type": parameter.type_name,
                "description": parameter.description,
            }),
        );
        if parameter.required {
            required.push(Value::String(parameter.name.clone()));
        }
    }
    let schema = Map::from_iter([
        ("type".into(), Value::String("object".into())),
        ("properties".into(), Value::Object(properties)),
        ("required".into(), Value::Array(required)),
        ("additionalProperties".into(), Value::Bool(false)),
    ]);
    let read_only = matches!(tool.kind, ConfiguredToolKind::Local)
        && !tool.command.to_ascii_lowercase().contains("rm ");
    Tool::new(
        Cow::Owned(tool.name.clone()),
        Cow::Owned(tool.description.clone()),
        Arc::new(schema),
    )
    .with_annotations(
        ToolAnnotations::new()
            .read_only(read_only)
            .destructive(!read_only)
            .open_world(matches!(
                tool.kind,
                ConfiguredToolKind::SshExec | ConfiguredToolKind::ScpUpload
            )),
    )
}

fn configured_tool_route(tool: ConfiguredTool) -> ToolRoute<McpServer> {
    let definition = configured_tool_schema(&tool);
    ToolRoute::new_dyn(definition, move |context| {
        let tool = tool.clone();
        Box::pin(async move { execute_configured_tool(&tool, context.arguments).await })
    })
}

fn configured_arguments(
    tool: &ConfiguredTool,
    arguments: Option<JsonObject>,
) -> Result<HashMap<String, String>, McpError> {
    let arguments = arguments.unwrap_or_default();
    let allowed: BTreeSet<&str> = tool
        .parameters
        .iter()
        .map(|item| item.name.as_str())
        .collect();
    if let Some(unknown) = arguments.keys().find(|key| !allowed.contains(key.as_str())) {
        return Err(McpServer::error(format!("unknown parameter {unknown:?}")));
    }
    let mut values = HashMap::new();
    for parameter in &tool.parameters {
        let Some(value) = arguments.get(&parameter.name) else {
            if parameter.required {
                return Err(McpServer::error(format!(
                    "missing required parameter {:?}",
                    parameter.name
                )));
            }
            continue;
        };
        let valid_type = match parameter.type_name.as_str() {
            "string" => value.is_string(),
            "integer" => value.as_i64().is_some() || value.as_u64().is_some(),
            "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            _ => false,
        };
        if !valid_type {
            return Err(McpServer::error(format!(
                "parameter {:?} must be a {}",
                parameter.name, parameter.type_name
            )));
        }
        let value = match value {
            Value::String(value) => value.clone(),
            Value::Bool(value) => value.to_string(),
            Value::Number(value) => value.to_string(),
            _ => unreachable!("parameter type validation rejected this value"),
        };
        if value.contains('\0') || value.contains('\n') || value.contains('\r') {
            return Err(McpServer::error(format!(
                "parameter {:?} cannot contain NUL or newline characters",
                parameter.name
            )));
        }
        values.insert(parameter.name.clone(), value);
    }
    Ok(values)
}

fn render_command(
    command: &str,
    values: &HashMap<String, String>,
) -> Result<Vec<String>, McpError> {
    let argv = shell_words::split(command)
        .map_err(|error| McpServer::error(format!("invalid command quoting: {error}")))?;
    if argv.is_empty() {
        return Err(McpServer::error("command cannot be empty"));
    }
    let placeholder_re = Regex::new(r"\{([A-Za-z_][A-Za-z0-9_]*)\}").expect("placeholder regex");
    argv.into_iter()
        .map(|argument| {
            let mut missing = None;
            let rendered = placeholder_re
                .replace_all(&argument, |captures: &regex::Captures<'_>| {
                    let name = &captures[1];
                    match values.get(name) {
                        Some(value) => value.clone(),
                        None => {
                            missing = Some(name.to_string());
                            String::new()
                        }
                    }
                })
                .into_owned();
            if let Some(name) = missing {
                return Err(McpServer::error(format!(
                    "command references missing parameter {name:?}"
                )));
            }
            Ok(rendered)
        })
        .collect()
}

async fn execute_configured_tool(
    tool: &ConfiguredTool,
    arguments: Option<JsonObject>,
) -> Result<CallToolResponse, McpError> {
    let values = configured_arguments(tool, arguments)?;
    let mut result = match tool.kind {
        ConfiguredToolKind::Local => {
            run_read_only(
                render_command(&tool.command, &values)?,
                tool.timeout_seconds,
                None,
                true,
            )
            .await
        }
        ConfiguredToolKind::SshExec => {
            let mut argv = vec!["ssh".into()];
            if tool.ssh_port != 0 {
                argv.extend(["-p".into(), tool.ssh_port.to_string()]);
            }
            if !tool.ssh_identity_file.trim().is_empty() {
                argv.extend(["-i".into(), tool.ssh_identity_file.clone()]);
            }
            argv.push(ssh_target(tool));
            let remote_command = render_command(&tool.command, &values)?;
            argv.push(shell_words::join(remote_command));
            run_read_only(argv, tool.timeout_seconds, None, true).await
        }
        ConfiguredToolKind::ScpUpload => {
            let source = PathBuf::from(&tool.upload_source);
            if !source.is_file() {
                return Ok(configured_result(
                    error_result(format!(
                        "upload source is not a regular file: {}",
                        source.display()
                    )),
                    "upload",
                    true,
                ));
            }
            let destination = values
                .get(&tool.upload_destination_parameter)
                .ok_or_else(|| McpServer::error("upload destination parameter is missing"))?;
            if destination.trim().is_empty() {
                return Err(McpServer::error("upload destination cannot be empty"));
            }
            let destination_re = Regex::new(r"^[A-Za-z0-9_./:@+~-]+$").expect("destination regex");
            if !destination_re.is_match(destination) {
                return Err(McpServer::error(
                    "upload destination may contain only path and host-safe characters",
                ));
            }
            let mut argv = vec!["scp".into()];
            if tool.ssh_port != 0 {
                argv.extend(["-P".into(), tool.ssh_port.to_string()]);
            }
            if !tool.ssh_identity_file.trim().is_empty() {
                argv.extend(["-i".into(), tool.ssh_identity_file.clone()]);
            }
            argv.push(source.display().to_string());
            argv.push(format!("{}:{}", ssh_target(tool), destination));
            let mut result = run_read_only(argv, tool.timeout_seconds, None, true).await;
            result.mode = "upload".into();
            result.mutating = true;
            result
        }
        ConfiguredToolKind::Docker => {
            let image = docker_image_name(&tool.name);
            let build = run_read_only(
                vec![
                    "docker".into(),
                    "build".into(),
                    "--file".into(),
                    tool.dockerfile.clone(),
                    "--tag".into(),
                    image.clone(),
                    tool.docker_context.clone(),
                ],
                tool.timeout_seconds,
                None,
                true,
            )
            .await;
            if build.exit_code != 0 {
                return Ok(configured_result(build, "docker_build", true));
            }
            let mut argv = vec!["docker".into(), "run".into(), "--rm".into()];
            for env_key in &tool.docker_env {
                if env::var(env_key).is_err() {
                    return Ok(configured_result(
                        error_result(format!(
                            "Docker secret environment variable {env_key:?} is not defined"
                        )),
                        "docker",
                        true,
                    ));
                }
                argv.extend(["--env".into(), env_key.clone()]);
            }
            argv.push(image);
            argv.extend(render_command(&tool.command, &values)?);
            let mut result = run_read_only(argv, tool.timeout_seconds, None, true).await;
            redact_configured_secrets(&mut result, &tool.docker_env);
            result
        }
    };
    let (mode, mutating) = match tool.kind {
        ConfiguredToolKind::Local => ("execute", true),
        ConfiguredToolKind::SshExec => ("ssh", true),
        ConfiguredToolKind::Docker => ("docker", true),
        ConfiguredToolKind::ScpUpload => ("upload", true),
    };
    result.mode = mode.into();
    result.mutating = mutating;
    Ok(configured_result(result, mode, mutating))
}

fn configured_result(result: CommandResult, _mode: &str, _mutating: bool) -> CallToolResponse {
    let text = serde_json::to_string_pretty(&result).unwrap_or_else(|error| error.to_string());
    CallToolResult::success(vec![ContentBlock::text(text)]).into()
}

fn redact_configured_secrets(result: &mut CommandResult, keys: &[String]) {
    for key in keys {
        let Ok(secret) = env::var(key) else {
            continue;
        };
        if secret.len() < 4 {
            continue;
        }
        let stdout_count = result.stdout.matches(&secret).count();
        let stderr_count = result.stderr.matches(&secret).count();
        result.stdout = result.stdout.replace(&secret, "[REDACTED]");
        result.stderr = result.stderr.replace(&secret, "[REDACTED]");
        if stdout_count + stderr_count > 0 {
            result.redaction_count += stdout_count + stderr_count;
            result.redactions.push(format!("docker_env:{key}"));
        }
    }
    result.redactions.sort();
    result.redactions.dedup();
}

fn ssh_target(tool: &ConfiguredTool) -> String {
    if tool.ssh_user.trim().is_empty() {
        tool.ssh_host.clone()
    } else {
        format!("{}@{}", tool.ssh_user, tool.ssh_host)
    }
}

fn docker_image_name(name: &str) -> String {
    let safe = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("command-mcp-tool-{safe}:latest")
}

#[tool_handler(
    router = self.tool_router,
    name = "Command MCP",
    version = "0.2.0",
    instructions = "Use only the explicitly exposed tools. Validate arguments and report tool errors without retrying destructive operations."
)]
impl ServerHandler for McpServer {}

pub async fn serve_stdio(settings: Settings) -> anyhow::Result<()> {
    let server = McpServer::new(settings)?;
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

pub async fn serve_http(settings: Settings) -> anyhow::Result<()> {
    let address = format!("{}:{}", settings.host, settings.port);
    let server = McpServer::new(settings.clone())?;
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true),
    );
    let public_routes = axum::Router::new().route(
        "/healthz",
        axum::routing::get(|| async {
            axum::Json(json!({"status": "ok", "transport": "streamable-http"}))
        }),
    );
    let mcp_routes = axum::Router::new().nest_service("/mcp", service);
    let app = if let Some(token) = settings.api_key {
        let protected_mcp_routes =
            mcp_routes.layer(axum::middleware::from_fn(move |request, next| {
                let token = token.clone();
                async move { auth_middleware(token, request, next).await }
            }));
        public_routes.merge(protected_mcp_routes)
    } else {
        public_routes.merge(mcp_routes)
    };
    let listener = tokio::net::TcpListener::bind(&address).await?;
    tracing::info!("Command MCP listening on http://{address}/mcp");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn auth_middleware(
    token: String,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use subtle::ConstantTimeEq;
    let supplied = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if supplied
        .map(|value| value.as_bytes().ct_eq(token.as_bytes()).into())
        .unwrap_or(false)
    {
        return next.run(request).await;
    }
    (
        axum::http::StatusCode::UNAUTHORIZED,
        [(axum::http::header::WWW_AUTHENTICATE, "Bearer")],
        axum::Json(json!({"error": "unauthorized"})),
    )
        .into_response()
}

fn bounded_arg(value: Option<String>, max: usize, name: &str) -> Result<Option<String>, McpError> {
    if let Some(value) = value {
        if value.len() > max {
            return Err(McpError::invalid_params(
                format!("{name} is too long"),
                None,
            ));
        }
        return Ok(Some(value));
    }
    Ok(None)
}

fn is_sensitive_path(path: &Path) -> bool {
    let sensitive_dirs = [".aws", ".gnupg", ".kube", ".ssh"];
    let sensitive_files = [
        ".netrc",
        ".npmrc",
        ".pypirc",
        "credentials",
        "credentials.json",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "service-account.json",
    ];
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    name == ".env"
        || name.starts_with(".env.")
        || sensitive_files.contains(&name.as_str())
        || path.components().any(|component| {
            sensitive_dirs.contains(&component.as_os_str().to_string_lossy().as_ref())
        })
        || (path
            .components()
            .any(|component| component.as_os_str() == ".config")
            && path
                .components()
                .any(|component| component.as_os_str() == "gcloud"))
}

struct Capture {
    bytes: Vec<u8>,
    truncated: bool,
}

struct CapturedStreams {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

async fn capture_stream<R: AsyncRead + Unpin>(mut reader: R, budget: Arc<Mutex<usize>>) -> Capture {
    use tokio::io::AsyncReadExt;
    let mut result = Capture {
        bytes: Vec::new(),
        truncated: false,
    };
    let mut chunk = [0_u8; 65536];
    while let Ok(size) = reader.read(&mut chunk).await {
        if size == 0 {
            break;
        }
        let mut remaining = budget.lock().await;
        let keep = size.min(*remaining);
        result.bytes.extend_from_slice(&chunk[..keep]);
        *remaining -= keep;
        if keep < size {
            result.truncated = true;
        }
    }
    result
}

pub async fn run_read_only(
    argv: Vec<String>,
    timeout_seconds: u64,
    env_overrides: Option<HashMap<String, String>>,
    stdin_null: bool,
) -> CommandResult {
    let started_at = Utc::now();
    let started = Instant::now();
    let executable = argv.first().cloned().unwrap_or_default();
    let mut command = Command::new(&executable);
    command
        .args(argv.iter().skip(1))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if stdin_null {
        command.stdin(Stdio::null());
    }
    if let Some(overrides) = env_overrides {
        command.envs(overrides);
    }
    let child = command.spawn();
    let Ok(mut child) = child else {
        let error = match child {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                format!("{executable} is not installed or not available in PATH\n")
            }
            Err(error) => format!("could not execute {executable}: {error}\n"),
            Ok(_) => String::new(),
        };
        let code = if error.contains("not installed") {
            127
        } else {
            126
        };
        return finish_result(
            CapturedStreams {
                stdout: Vec::new(),
                stderr: error.into_bytes(),
                stdout_truncated: false,
                stderr_truncated: false,
            },
            code,
            started_at,
            started.elapsed(),
            false,
        );
    };
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let budget = Arc::new(Mutex::new(MAX_OUTPUT_BYTES));
    let stdout_task = tokio::spawn(capture_stream(stdout, budget.clone()));
    let stderr_task = tokio::spawn(capture_stream(stderr, budget));
    let wait = timeout(Duration::from_secs(timeout_seconds), child.wait()).await;
    let (exit_code, timed_out) = match wait {
        Ok(Ok(status)) => (status.code().unwrap_or(1), false),
        Ok(Err(_error)) => (126, false),
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            (124, true)
        }
    };
    let stdout = stdout_task.await.unwrap_or(Capture {
        bytes: Vec::new(),
        truncated: false,
    });
    let mut stderr = stderr_task.await.unwrap_or(Capture {
        bytes: Vec::new(),
        truncated: false,
    });
    if timed_out {
        stderr.bytes.extend_from_slice(
            format!("{executable} timed out after {timeout_seconds} seconds\n").as_bytes(),
        );
    }
    let stdout_truncated = stdout.truncated;
    let stderr_truncated = stderr.truncated;
    finish_result(
        CapturedStreams {
            stdout: stdout.bytes,
            stderr: stderr.bytes,
            stdout_truncated,
            stderr_truncated,
        },
        exit_code,
        started_at,
        started.elapsed(),
        timed_out,
    )
}

fn finish_result(
    captured: CapturedStreams,
    exit_code: i32,
    started_at: DateTime<Utc>,
    elapsed: Duration,
    timed_out: bool,
) -> CommandResult {
    let (stdout, stdout_count, mut redactions) =
        redact(String::from_utf8_lossy(&captured.stdout).into_owned());
    let (stderr, stderr_count, stderr_redactions) =
        redact(String::from_utf8_lossy(&captured.stderr).into_owned());
    redactions.extend(stderr_redactions);
    redactions.sort();
    redactions.dedup();
    CommandResult {
        stdout,
        stderr,
        exit_code,
        started_at,
        ended_at: Utc::now(),
        duration_ms: elapsed.as_millis() as u64,
        host: hostname(),
        mode: "inspect".into(),
        mutating: false,
        timed_out,
        stdout_truncated: captured.stdout_truncated,
        stderr_truncated: captured.stderr_truncated,
        redaction_count: stdout_count + stderr_count,
        redactions,
    }
}

fn hostname() -> String {
    env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn redact(mut text: String) -> (String, usize, Vec<String>) {
    let patterns: &[(&str, &str, &str)] = &[
        (
            r"(?im)^(\s*(?:authorization|proxy-authorization)\s*:\s*)[^\r\n]+",
            "$1[REDACTED]",
            "authorization_header",
        ),
        (
            r"(?im)^(\s*(?:cookie|set-cookie)\s*:\s*)[^\r\n]+",
            "$1[REDACTED]",
            "cookie_header",
        ),
        (
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            "[REDACTED PRIVATE KEY]",
            "private_key",
        ),
        (
            r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/=-]+",
            "$1[REDACTED]",
            "bearer_token",
        ),
        (
            r#"(?im)([\"']?(?:api[_-]?key|client[_-]?secret|passwd|password|secret(?:access)?key|token)[\"']?\s*[:=]\s*)(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"#,
            "$1[REDACTED]",
            "credential_field",
        ),
    ];
    let mut count = 0;
    let mut categories = Vec::new();
    for (pattern, replacement, category) in patterns {
        let regex = Regex::new(pattern).expect("redaction regex");
        let replacement_count = regex.find_iter(&text).count();
        text = regex.replace_all(&text, *replacement).into_owned();
        if replacement_count > 0 {
            count += replacement_count;
            categories.push((*category).to_string());
        }
    }
    (text, count, categories)
}

async fn run_cloud_command(
    command_text: &str,
    executable: &str,
    allowed: &[&[&str]],
) -> CommandResult {
    let Ok(argv) = shell_words::split(command_text) else {
        return error_result("invalid command: could not parse shell quoting".to_string());
    };
    if argv.first().map(String::as_str) != Some(executable) {
        return error_result(format!("command does not start with {executable}"));
    }
    let allowed_command = allowed.iter().any(|prefix| {
        argv.get(1..)
            .map(|args| {
                args.len() >= prefix.len()
                    && args
                        .iter()
                        .zip(*prefix)
                        .all(|(actual, expected)| actual == expected)
            })
            .unwrap_or(false)
    });
    if !allowed_command {
        return error_result(format!(
            "{executable} command is not in the read-only allowlist"
        ));
    }
    let mut environment: HashMap<String, String> = env::vars().collect();
    environment.extend([
        ("AWS_PAGER".into(), "".into()),
        ("AWS_CLI_AUTO_PROMPT".into(), "off".into()),
        ("CLOUDSDK_CORE_DISABLE_PROMPTS".into(), "1".into()),
        ("CLOUDSDK_PAGER".into(), "".into()),
    ]);
    run_read_only(argv, 15, Some(environment), true).await
}

fn error_result(message: String) -> CommandResult {
    let now = Utc::now();
    CommandResult {
        stdout: String::new(),
        stderr: message,
        exit_code: 1,
        started_at: now,
        ended_at: now,
        duration_ms: 0,
        host: hostname(),
        mode: "inspect".into(),
        mutating: false,
        timed_out: false,
        stdout_truncated: false,
        stderr_truncated: false,
        redaction_count: 0,
        redactions: Vec::new(),
    }
}

fn read_attributes(entry: &Path, attributes: &[&str]) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    if let Ok(path) = entry.canonicalize() {
        values.insert("path".into(), path.display().to_string());
    }
    for attribute in attributes {
        let target = entry.join(attribute);
        let Ok(bytes) = std::fs::read(&target) else {
            continue;
        };
        if *attribute == "edid" {
            values.insert("edid_bytes".into(), bytes.len().to_string());
        } else {
            values.insert(
                (*attribute).to_string(),
                String::from_utf8_lossy(&bytes).trim().to_string(),
            );
        }
    }
    values
}

fn sysfs_collection(
    root: &Path,
    attributes: &[&str],
    name_filter: Option<&str>,
) -> BTreeMap<String, BTreeMap<String, String>> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return BTreeMap::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    paths.sort_by_key(|path| path.file_name().map(|name| name.to_os_string()));
    paths
        .into_iter()
        .filter_map(|path| {
            let name = path.file_name()?.to_string_lossy().to_string();
            if let Some(filter) = name_filter
                && !matches_simple_filter(&name, filter)
            {
                return None;
            }
            Some((name, read_attributes(&path, attributes)))
        })
        .collect()
}

fn matches_simple_filter(name: &str, filter: &str) -> bool {
    match filter {
        "card*-*" => name.starts_with("card") && name.contains('-'),
        _ => name == filter,
    }
}

fn drm_connectors() -> BTreeMap<String, BTreeMap<String, String>> {
    let mut connectors = sysfs_collection(
        Path::new("/sys/class/drm"),
        &["status", "enabled", "dpms", "modes", "edid"],
        Some("card*-*"),
    );
    let pci_re = Regex::new(r"^(?:[0-9A-Fa-f]{4}:)?[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\.[0-7]$")
        .expect("PCI address regex");
    for (name, values) in &mut connectors {
        let entry = Path::new("/sys/class/drm").join(name);
        let device = entry.join("device");
        if let Ok(resolved) = device.canonicalize() {
            values.insert("device_path".into(), resolved.display().to_string());
            if let Some(pci) = resolved.ancestors().find(|parent| {
                pci_re.is_match(&parent.file_name().unwrap_or_default().to_string_lossy())
            }) {
                let address = pci
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                values.insert("pci_address".into(), address.clone());
                if let Ok(driver) = pci.join("driver").canonicalize() {
                    values.insert(
                        "driver".into(),
                        driver
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into(),
                    );
                }
            }
        }
    }
    connectors
}

fn bounded_text(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let bytes = &bytes[..bytes.len().min(MAX_OUTPUT_BYTES)];
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn nvidia_state() -> BTreeMap<String, BTreeMap<String, String>> {
    let mut state = BTreeMap::new();
    for module in [
        "nvidia",
        "nvidia_drm",
        "nvidia_modeset",
        "nvidia_uvm",
        "nouveau",
    ] {
        let module_dir = Path::new("/sys/module").join(module);
        let mut values = BTreeMap::new();
        values.insert("loaded".into(), module_dir.is_dir().to_string());
        let parameters = module_dir.join("parameters");
        if let Ok(entries) = std::fs::read_dir(parameters) {
            for entry in entries.flatten() {
                if let Some(value) = bounded_text(&entry.path()) {
                    values.insert(
                        format!("parameter.{}", entry.file_name().to_string_lossy()),
                        value.trim().into(),
                    );
                }
            }
        }
        state.insert(format!("module:{module}"), values);
    }
    for relative in ["version", "params"] {
        if let Some(value) = bounded_text(&Path::new("/proc/driver/nvidia").join(relative)) {
            state.insert(
                format!("proc:{relative}"),
                BTreeMap::from([(String::from("value"), value)]),
            );
        }
    }
    let gpu_root = Path::new("/proc/driver/nvidia/gpus");
    if let Ok(entries) = std::fs::read_dir(gpu_root) {
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                state.insert(
                    format!("gpu:{}", entry.file_name().to_string_lossy()),
                    read_attributes(&entry.path(), &["information", "power"]),
                );
            }
        }
    }
    {
        let address = "0000:01:00.0";
        let entry = Path::new("/sys/bus/pci/devices").join(address);
        if entry.is_dir() {
            let mut values = read_attributes(
                &entry,
                &[
                    "enable",
                    "power_state",
                    "power/control",
                    "power/runtime_status",
                ],
            );
            values.insert(
                "driver".into(),
                entry
                    .join("driver")
                    .canonicalize()
                    .ok()
                    .and_then(|path| path.file_name().map(|name| name.to_string_lossy().into()))
                    .unwrap_or_else(|| "unbound".into()),
            );
            state.insert(format!("pci:{address}"), values);
        }
    }
    state
}

fn assess_display(
    pci: &CommandResult,
    modules: &CommandResult,
    typec: &BTreeMap<String, BTreeMap<String, String>>,
    connectors: &BTreeMap<String, BTreeMap<String, String>>,
    nvidia: &CommandResult,
    nvidia_module: &CommandResult,
) -> Vec<DiagnosticFinding> {
    let mut findings = Vec::new();
    let pci_text = pci.stdout.to_ascii_lowercase();
    let module_names: BTreeSet<String> = modules
        .stdout
        .lines()
        .filter_map(|line| line.split_whitespace().next().map(str::to_string))
        .collect();
    let nvidia_present = pci_text.contains("nvidia");
    let nvidia_bound = pci.stdout.lines().any(|line| {
        let line = line.to_ascii_lowercase();
        line.contains("kernel driver in use:") && line.contains("nvidia")
    });
    if nvidia_present && !nvidia_bound {
        findings.push(DiagnosticFinding {
            severity: "error".into(),
            code: "nvidia_present_unbound".into(),
            summary: "An NVIDIA GPU is present but no kernel driver is bound to it.".into(),
            evidence: vec!["lspci reports NVIDIA hardware without 'Kernel driver in use'.".into()],
            recommendation: Some("Install/fix the matching NVIDIA driver, then reboot.".into()),
        });
    }
    if nvidia_present
        && (nvidia_module.exit_code == 127
            || nvidia_module
                .stderr
                .to_ascii_lowercase()
                .contains("module nvidia not found"))
    {
        findings.push(DiagnosticFinding {
            severity: "error".into(),
            code: "nvidia_module_missing".into(),
            summary: "The NVIDIA kernel module is not installed for this system.".into(),
            evidence: vec![nvidia_module.stderr.trim().into()],
            recommendation: Some(
                "Install the distribution-recommended NVIDIA driver package.".into(),
            ),
        });
    } else if nvidia_present && !module_names.contains("nvidia") {
        findings.push(DiagnosticFinding {
            severity: "warning".into(),
            code: "nvidia_module_not_loaded".into(),
            summary: "NVIDIA hardware exists, but the NVIDIA module is not loaded.".into(),
            evidence: vec![if nvidia.stderr.trim().is_empty() {
                format!("nvidia-smi exit code {}", nvidia.exit_code)
            } else {
                nvidia.stderr.trim().into()
            }],
            recommendation: Some(
                "Check DKMS, Secure Boot, module conflicts, and kernel logs.".into(),
            ),
        });
    }
    let external_connector_re = Regex::new(r"-(?:eDP|LVDS|DSI)-").expect("connector regex");
    let external_connected = connectors.iter().any(|(name, values)| {
        values.get("status").map(String::as_str) == Some("connected")
            && !external_connector_re.is_match(name)
            && !name.to_ascii_lowercase().contains("writeback")
    });
    if !external_connected {
        findings.push(DiagnosticFinding {
            severity: "warning".into(),
            code: "no_external_drm_sink".into(),
            summary: "No DRM connector currently reports a connected external display.".into(),
            evidence: vec!["No connector has status=connected.".into()],
            recommendation: None,
        });
    }
    if typec.is_empty() {
        findings.push(DiagnosticFinding {
            severity: "warning".into(),
            code: "no_typec_class_devices".into(),
            summary: "Linux exposes no USB Type-C class devices.".into(),
            evidence: vec!["/sys/class/typec is absent or empty.".into()],
            recommendation: Some(
                "Check UCSI/Type-C driver binding and ACPI firmware errors.".into(),
            ),
        });
    }
    if findings.is_empty() {
        findings.push(DiagnosticFinding {
            severity: "info".into(),
            code: "no_obvious_failure".into(),
            summary: "The snapshot contains no immediately classifiable display failure.".into(),
            evidence: Vec::new(),
            recommendation: None,
        });
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_credentials() {
        let (text, count, categories) =
            redact("password=hunter2\nAuthorization: Bearer header.payload.signature".into());
        assert!(!text.contains("hunter2"));
        assert!(!text.contains("header.payload.signature"));
        assert_eq!(count, 2);
        assert_eq!(categories, vec!["authorization_header", "credential_field"]);
    }

    #[test]
    fn default_commands_leave_privileged_tool_disabled() {
        assert!(!crate::default_enabled_commands().contains("kmode_root"));
        assert!(crate::default_enabled_commands().contains("display_diagnostics"));
    }

    #[test]
    fn server_hides_disabled_tools() {
        let server = McpServer::new(crate::Settings {
            host: "127.0.0.1".into(),
            port: 8000,
            api_key: None,
            read_roots: vec![PathBuf::from(".")],
            allow_unauthenticated_remote: false,
            allow_sensitive_file_reads: false,
            config_path: PathBuf::from(".command-mcp.toml"),
            enabled_commands: crate::default_enabled_commands(),
            configured_tools: Vec::new(),
        })
        .unwrap();
        assert!(server.get_tool("kmode_root").is_none());
        assert!(server.get_tool("health").is_some());
    }

    #[test]
    fn server_registers_configured_tool_with_generated_schema() {
        let tool = ConfiguredTool {
            name: "say_message".into(),
            description: "Say a message.".into(),
            kind: ConfiguredToolKind::Local,
            enabled: true,
            command: "echo {message}".into(),
            parameters: vec![crate::ToolParameter {
                name: "message".into(),
                description: "Text to print.".into(),
                type_name: "string".into(),
                required: true,
            }],
            ..ConfiguredTool::default()
        };
        let server = McpServer::new(crate::Settings {
            host: "127.0.0.1".into(),
            port: 8000,
            api_key: None,
            read_roots: vec![PathBuf::from(".")],
            allow_unauthenticated_remote: false,
            allow_sensitive_file_reads: false,
            config_path: PathBuf::from(".command-mcp.toml"),
            enabled_commands: crate::default_enabled_commands(),
            configured_tools: vec![tool],
        })
        .unwrap();
        let definition = server.get_tool("say_message").expect("configured tool");
        assert_eq!(definition.name, "say_message");
        assert_eq!(definition.input_schema["required"][0], "message");
    }

    #[test]
    fn command_placeholders_are_replaced_without_shell_expansion() {
        let values = HashMap::from([(String::from("value"), String::from("hello world"))]);
        assert_eq!(
            render_command("printf '%s' {value}", &values).unwrap(),
            vec!["printf", "%s", "hello world"]
        );
    }
}
