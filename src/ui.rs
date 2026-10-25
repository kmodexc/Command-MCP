mod ui_server;

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
};

use zeroize::Zeroize;

use command_mcp::{
    COMMAND_GROUPS, COMMAND_SPECS, CommandConfig, CommandGroup, ConfiguredTool, ConfiguredToolKind,
    SshAuthentication, ToolParameter, command_config_path, default_enabled_commands,
    ensure_env_api_key, env_file_path, load_command_config, load_env_file, save_command_config,
    save_env_file,
};
use command_mcp::{commands::validate_configured_tools, ssh::SshControlEvent};
use ui_server::{ServerLaunchConfig, ServerProcess};

#[derive(Clone, PartialEq, Eq)]
enum Selection {
    BuiltIn(String),
    Configured(usize),
    Environment,
}

struct CommandMcpApp {
    config_path: PathBuf,
    config: CommandConfig,
    selection: Option<Selection>,
    server: Option<ServerProcess>,
    status: String,
    error_message: Option<String>,
    env_path: PathBuf,
    env_values: BTreeMap<String, String>,
    reveal_secrets: bool,
    restart_required: bool,
    docker_env_draft: String,
    dockerfile_drafts: BTreeMap<String, String>,
    new_env_key: String,
    ssh_password_draft: String,
    ssh_password_tool: Option<String>,
}

impl CommandMcpApp {
    fn new() -> Self {
        let mut startup_errors = Vec::new();
        let config_path = command_config_path().unwrap_or_else(|error| {
            startup_errors.push(format!(
                "Could not determine the application config directory: {error}"
            ));
            PathBuf::new()
        });
        let mut config = match load_command_config(&config_path) {
            Ok(config) => config,
            Err(error) => {
                startup_errors.push(format!(
                    "Could not load configuration {}: {error}",
                    config_path.display()
                ));
                CommandConfig::default()
            }
        };
        if config.enabled_commands.is_none() {
            config.enabled_commands = Some(default_enabled_commands());
        }
        let env_path = match env_file_path(&config) {
            Ok(path) => path,
            Err(error) => {
                startup_errors.push(format!(
                    "Could not determine the application data directory: {error}"
                ));
                PathBuf::new()
            }
        };
        let mut env_values = match load_env_file(&env_path) {
            Ok(values) => values,
            Err(error) => {
                startup_errors.push(format!(
                    "Could not load environment file {}: {error}",
                    env_path.display()
                ));
                BTreeMap::new()
            }
        };
        if config.server.auth_enabled
            && env_values
                .get("COMMAND_MCP_API_KEY")
                .is_none_or(String::is_empty)
        {
            match ensure_env_api_key(&env_path) {
                Ok(key) => {
                    env_values.insert("COMMAND_MCP_API_KEY".into(), key);
                }
                Err(error) => startup_errors.push(format!(
                    "Could not create an API password in {}: {error}",
                    env_path.display()
                )),
            }
        }
        let mut app = Self {
            config_path,
            config,
            selection: None,
            server: None,
            status: "Starting the local MCP server…".into(),
            error_message: None,
            env_path,
            env_values,
            reveal_secrets: false,
            restart_required: false,
            docker_env_draft: String::new(),
            dockerfile_drafts: BTreeMap::new(),
            new_env_key: String::new(),
            ssh_password_draft: String::new(),
            ssh_password_tool: None,
        };
        if let Err(error) = app.start_server() {
            startup_errors.push(error);
        }
        app.status = if startup_errors.is_empty() {
            app.running_status()
        } else {
            format!(
                "Startup errors:\n{}{}",
                startup_errors
                    .iter()
                    .map(|error| format!("• {error}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
                if app.server.is_some() {
                    format!("\nServer status: {}", app.running_status())
                } else {
                    String::new()
                }
            )
        };
        if !startup_errors.is_empty() {
            app.error_message = Some(app.status.clone());
        }
        app
    }

    fn running_status(&self) -> String {
        format!(
            "Server running at http://{}:{}/mcp",
            self.config.server.host, self.config.server.port
        )
    }

    fn report_error(&mut self, context: &str, error: impl std::fmt::Display) {
        self.set_error(format!("{context}: {error}"));
    }

    fn set_status(&mut self, status: impl Into<String>) {
        self.status = status.into();
        self.error_message = None;
    }

    fn set_error(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.status = message.clone();
        self.error_message = Some(message);
    }

    fn enabled_commands(&mut self) -> &mut BTreeSet<String> {
        self.config
            .enabled_commands
            .get_or_insert_with(default_enabled_commands)
    }

    fn command_enabled(&self, name: &str) -> bool {
        self.config
            .enabled_commands
            .as_ref()
            .is_some_and(|commands| commands.contains(name))
    }

    fn set_builtin_group_enabled(&mut self, group: &CommandGroup, enabled: bool) {
        let commands = self.enabled_commands();
        for name in group.command_names {
            if enabled {
                commands.insert((*name).into());
            } else {
                commands.remove(*name);
            }
        }
        self.restart_required = true;
    }

    fn set_configured_tools_enabled(&mut self, enabled: bool) {
        for tool in &mut self.config.tools {
            tool.enabled = enabled;
        }
        self.restart_required = true;
    }

    fn persist_changes(&mut self) -> Result<(), String> {
        self.sync_dockerfiles()?;
        validate_configured_tools(&self.config.tools)
            .map_err(|error| format!("tool configuration is invalid: {error}"))?;
        self.config.server.env_file = self.env_path.display().to_string();
        let enabled = self
            .config
            .enabled_commands
            .clone()
            .unwrap_or_else(default_enabled_commands);
        if self.config.server.auth_enabled {
            let key = ensure_env_api_key(&self.env_path)?;
            self.env_values.insert("COMMAND_MCP_API_KEY".into(), key);
        }
        save_env_file(&self.env_path, &self.env_values)?;
        save_command_config(
            &self.config_path,
            &enabled,
            &self.config.tools,
            &self.config.server,
        )?;
        self.config.enabled_commands = Some(enabled);
        Ok(())
    }

    fn prepare_dockerfile(&mut self, index: usize) -> Result<(), String> {
        let tool = self
            .config
            .tools
            .get(index)
            .ok_or_else(|| "configured tool no longer exists".to_string())?;
        if tool.kind != ConfiguredToolKind::Docker {
            return Ok(());
        }
        let name = tool.name.clone();
        let legacy_path = tool.dockerfile.clone();
        let managed_path = command_mcp::managed_dockerfile_path(&name)?;
        if !self.dockerfile_drafts.contains_key(&name) {
            let content = fs::read_to_string(&managed_path)
                .or_else(|_| {
                    if legacy_path.trim().is_empty() {
                        Err(std::io::Error::from(std::io::ErrorKind::NotFound))
                    } else {
                        fs::read_to_string(&legacy_path)
                    }
                })
                .unwrap_or_default();
            self.dockerfile_drafts.insert(name.clone(), content);
        }
        if self.config.tools[index].dockerfile != managed_path.display().to_string() {
            self.config.tools[index].dockerfile = managed_path.display().to_string();
            self.restart_required = true;
        }
        Ok(())
    }

    fn sync_dockerfiles(&mut self) -> Result<(), String> {
        for index in 0..self.config.tools.len() {
            if self.config.tools[index].kind != ConfiguredToolKind::Docker {
                continue;
            }
            self.prepare_dockerfile(index)?;
            let name = self.config.tools[index].name.clone();
            let path = command_mcp::managed_dockerfile_path(&name)?;
            let content = self
                .dockerfile_drafts
                .get(&name)
                .cloned()
                .unwrap_or_default();
            command_mcp::save_dockerfile_content(&path, &content)?;
        }
        Ok(())
    }

    fn save_changes(&mut self) {
        match self.persist_changes() {
            Ok(()) => {
                self.restart_required = true;
                self.set_status("Changes saved. Restart required to apply them.");
            }
            Err(error) => self.report_error("Could not save changes", error),
        }
    }

    fn save_and_restart(&mut self) {
        if let Err(error) = self.persist_changes() {
            self.report_error("Could not save changes", error);
            return;
        }
        self.restart_server();
    }

    fn start_server(&mut self) -> Result<(), String> {
        if self.server.is_some() {
            return Ok(());
        }
        let launch = ServerLaunchConfig {
            binary: None,
            config_path: &self.config_path,
            env_path: &self.env_path,
            host: &self.config.server.host,
            port: self.config.server.port,
            auth_enabled: self.config.server.auth_enabled,
            allow_unauthenticated_remote: self.config.server.allow_unauthenticated_remote,
            env_values: &self.env_values,
        };
        self.server = Some(ServerProcess::start(&launch)?);
        Ok(())
    }

    fn stop_server(&mut self) -> Result<(), String> {
        if let Some(server) = self.server.take() {
            server.stop()?;
        }
        self.set_status("Server stopped.");
        Ok(())
    }

    fn connect_ssh_password(&mut self, tool: String) {
        if self.restart_required {
            self.set_error("Save the tool and restart the server before opening an SSH session.");
            return;
        }
        let password = std::mem::take(&mut self.ssh_password_draft);
        if password.is_empty() {
            self.set_error("Enter the SSH password before connecting.");
            return;
        }
        let Some(server) = self.server.as_mut() else {
            self.set_error("The MCP server is not running.");
            return;
        };
        match server.send_control(command_mcp::ssh::SshControlRequest::Connect {
            tool,
            password: command_mcp::ssh::SensitiveString::new(password),
        }) {
            Ok(()) => self.set_status("SSH access request sent to the server."),
            Err(error) => self.report_error("Could not request SSH access", error),
        }
    }

    fn revoke_ssh_password(&mut self, tool: String) {
        let Some(server) = self.server.as_mut() else {
            self.set_error("The MCP server is not running.");
            return;
        };
        match server.send_control(command_mcp::ssh::SshControlRequest::Revoke { tool }) {
            Ok(()) => self.set_status("SSH access revoked."),
            Err(error) => self.report_error("Could not revoke SSH access", error),
        }
    }

    fn restart_server(&mut self) {
        let stop_error = self.stop_server().err();
        let start_error = self.start_server().err();
        let stopped_with_error = stop_error.is_some();
        let started_with_error = start_error.is_some();
        self.restart_required = started_with_error;
        let errors = [
            stop_error
                .as_deref()
                .map(|error| format!("Could not stop the server: {error}")),
            start_error
                .as_deref()
                .map(|error| format!("Could not start the server: {error}")),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        if !errors.is_empty() {
            self.set_error(errors.join("\n"));
        } else if !stopped_with_error && !started_with_error {
            let status = self.running_status();
            self.set_status(status);
        }
    }

    fn poll_server(&mut self) {
        self.poll_control_events();
        let exit = match self.server.as_mut() {
            Some(server) => match server.try_wait() {
                Ok(exit) => exit,
                Err(error) => {
                    self.report_error("Could not check the server process", error);
                    return;
                }
            },
            None => return,
        };
        if let Some(exit) = exit {
            self.server.take();
            self.restart_required = true;
            let details = exit.stderr.trim();
            self.set_error(if details.is_empty() {
                format!(
                    "Server exited ({}). Use Restart to launch it again.",
                    exit.status
                )
            } else {
                format!("Server exited ({}): {details}", exit.status)
            });
        }
    }

    fn poll_control_events(&mut self) {
        let events = self
            .server
            .as_mut()
            .map(ServerProcess::drain_control_events)
            .unwrap_or_default();
        for line in events {
            match serde_json::from_str::<SshControlEvent>(&line) {
                Ok(SshControlEvent::Connected { tool }) => {
                    self.set_status(format!("SSH access granted for tool {tool:?}."));
                }
                Ok(SshControlEvent::Revoked { tool }) => {
                    self.set_status(format!("SSH access revoked for tool {tool:?}."));
                }
                Ok(SshControlEvent::Error { tool, message }) => {
                    self.set_error(match tool {
                        Some(tool) => format!("SSH tool {tool:?} failed: {message}"),
                        None => format!("Server control error: {message}"),
                    });
                }
                Err(error) => {
                    self.report_error("Could not read a server control event", error);
                }
            }
        }
    }

    fn add_tool(&mut self) {
        self.add_tool_kind(ConfiguredToolKind::Local);
    }

    fn add_tool_kind(&mut self, kind: ConfiguredToolKind) {
        let mut tool = ConfiguredTool::default();
        tool.kind = kind;
        let base = tool.name.clone();
        let mut suffix = 2;
        while self.config.tools.iter().any(|item| item.name == tool.name) {
            tool.name = format!("{base}_{suffix}");
            suffix += 1;
        }
        self.config.tools.push(tool);
        self.selection = Some(Selection::Configured(self.config.tools.len() - 1));
        self.restart_required = true;
    }

    fn draw_builtin_editor(&mut self, ui: &mut egui::Ui, name: &str) {
        let Some(spec) = COMMAND_SPECS.iter().find(|spec| spec.name == name) else {
            return;
        };
        let was_enabled = self.enabled_commands().contains(name);
        let mut enabled = was_enabled;
        ui.heading(spec.name);
        ui.label(spec.description);
        ui.add_space(10.0);
        if ui
            .checkbox(&mut enabled, "Expose this built-in MCP command")
            .changed()
        {
            if enabled {
                self.enabled_commands().insert(name.to_string());
            } else {
                self.enabled_commands().remove(name);
            }
            self.restart_required = true;
        }
        if spec.privileged {
            ui.colored_label(
                egui::Color32::RED,
                "This command is privileged and is disabled by default.",
            );
        }
        ui.add_space(12.0);
        ui.label("Built-in commands use the server's built-in argument schema. Custom parameters are available for configured tools.");
    }

    fn draw_environment_editor(&mut self, ui: &mut egui::Ui) {
        ui.heading("Server and environment");
        ui.label("Authentication and Docker secrets are loaded from the selected .env file.");
        ui.add_space(10.0);

        egui::Grid::new("server_properties")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Environment file");
                let changed = ui
                    .text_edit_singleline(&mut self.config.server.env_file)
                    .changed();
                if changed {
                    self.restart_required = true;
                }
                if ui.button("Load").clicked() {
                    let path = PathBuf::from(&self.config.server.env_file);
                    match load_env_file(&path) {
                        Ok(values) => {
                            self.env_path = path;
                            self.env_values = values;
                            self.set_status(
                                "Environment file loaded. Save changes, then restart the server.",
                            );
                            self.restart_required = true;
                        }
                        Err(error) => self.report_error("Could not load environment file", error),
                    }
                }
                ui.end_row();
                ui.label("Bind host");
                if ui
                    .text_edit_singleline(&mut self.config.server.host)
                    .changed()
                {
                    self.restart_required = true;
                }
                ui.end_row();
                ui.label("Port");
                if ui
                    .add(egui::DragValue::new(&mut self.config.server.port).range(1..=65535))
                    .changed()
                {
                    self.restart_required = true;
                }
                ui.end_row();
                ui.label("Bearer authentication");
                if ui
                    .checkbox(&mut self.config.server.auth_enabled, "Require API password")
                    .changed()
                {
                    self.restart_required = true;
                }
                ui.end_row();
                ui.label("Unauthenticated remote bind");
                if ui
                    .checkbox(
                        &mut self.config.server.allow_unauthenticated_remote,
                        "Allow only with explicit approval",
                    )
                    .changed()
                {
                    self.restart_required = true;
                }
                ui.end_row();
            });

        ui.add_space(12.0);
        ui.heading("MCP API password");
        if self.config.server.auth_enabled {
            let value = self
                .env_values
                .entry("COMMAND_MCP_API_KEY".into())
                .or_default();
            ui.horizontal(|ui| {
                let changed = ui
                    .add(egui::TextEdit::singleline(value).password(!self.reveal_secrets))
                    .changed();
                if changed {
                    self.restart_required = true;
                }
                ui.checkbox(&mut self.reveal_secrets, "Show");
            });
            ui.small("A cryptographically random password is generated and written to the environment file when none exists.");
        } else {
            ui.colored_label(
                egui::Color32::YELLOW,
                "Authentication is disabled. A remote bind also requires the explicit unauthenticated-bind option.",
            );
        }

        ui.add_space(12.0);
        ui.heading("Environment variables");
        ui.small("Docker tools can pass selected variables into containers without putting their values in the Docker command line.");
        let mut remove_key = None;
        let keys = self
            .env_values
            .keys()
            .filter(|key| *key != "COMMAND_MCP_API_KEY")
            .cloned()
            .collect::<Vec<_>>();
        for key in keys {
            let is_secret = is_secret_key(&key);
            let mut changed = false;
            ui.horizontal(|ui| {
                ui.label(&key);
                if let Some(value) = self.env_values.get_mut(&key) {
                    changed = ui
                        .add(
                            egui::TextEdit::singleline(value)
                                .password(is_secret && !self.reveal_secrets),
                        )
                        .changed();
                }
                if ui.button("Remove").clicked() {
                    remove_key = Some(key.clone());
                }
            });
            if changed {
                self.restart_required = true;
            }
        }
        if let Some(key) = remove_key {
            self.env_values.remove(&key);
            self.restart_required = true;
        }
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.new_env_key);
            if ui.button("Add variable").clicked() {
                let key = self.new_env_key.trim().to_string();
                if is_valid_env_key(&key) {
                    self.env_values.entry(key).or_default();
                    self.new_env_key.clear();
                    self.restart_required = true;
                } else {
                    self.report_error(
                        "Could not add environment variable",
                        "names may contain only letters, digits, and underscores, and cannot start with a digit",
                    );
                }
            }
        });
        ui.add_space(16.0);
        ui.colored_label(
            egui::Color32::YELLOW,
            "Changes to authentication, bind settings, and environment values require a server restart.",
        );
    }

    fn draw_tool_editor(&mut self, ui: &mut egui::Ui, index: usize) -> (bool, bool) {
        let mut save = false;
        let mut delete = false;
        let mut connect_password = false;
        let mut revoke_password = false;
        if index >= self.config.tools.len() {
            return (save, delete);
        }
        let selected_tool_name = self.config.tools[index].name.clone();
        if self.ssh_password_tool.as_deref() != Some(selected_tool_name.as_str()) {
            self.ssh_password_draft.zeroize();
            self.ssh_password_tool = Some(selected_tool_name);
        }
        if let Err(error) = self.prepare_dockerfile(index) {
            self.report_error("Could not prepare Dockerfile storage", error);
        }
        let original = self.config.tools[index].clone();
        let tool = &mut self.config.tools[index];
        ui.horizontal(|ui| {
            ui.heading("Configured tool");
            ui.checkbox(&mut tool.enabled, "enabled");
        });
        ui.separator();
        egui::Grid::new("tool_properties")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("Name");
                ui.text_edit_singleline(&mut tool.name);
                ui.end_row();
                ui.label("Description");
                ui.add(egui::TextEdit::multiline(&mut tool.description).desired_rows(2));
                ui.end_row();
                ui.label("Kind");
                egui::ComboBox::from_id_salt("tool_kind")
                    .selected_text(kind_label(&tool.kind))
                    .show_ui(ui, |ui| {
                        for kind in [
                            ConfiguredToolKind::Local,
                            ConfiguredToolKind::SshExec,
                            ConfiguredToolKind::ScpUpload,
                            ConfiguredToolKind::Docker,
                        ] {
                            ui.selectable_value(&mut tool.kind, kind.clone(), kind_label(&kind));
                        }
                    });
                ui.end_row();
                ui.label("Timeout (seconds)");
                ui.add(egui::DragValue::new(&mut tool.timeout_seconds).range(1..=3600));
                ui.end_row();
            });

        ui.add_space(12.0);
        ui.label("Command template");
        ui.small("Use shell-like quoting. Put parameter names in braces, for example: echo {message}. The command is executed without a local shell.");
        ui.add(
            egui::TextEdit::multiline(&mut tool.command)
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );

        if matches!(
            tool.kind,
            ConfiguredToolKind::SshExec | ConfiguredToolKind::ScpUpload
        ) {
            ui.add_space(12.0);
            ui.label("SSH connection");
            let mut use_agent = tool.ssh_identity_file.trim().is_empty();
            let mut authentication = tool.ssh_authentication.clone();
            let password_auth = tool.kind == ConfiguredToolKind::SshExec
                && authentication == SshAuthentication::Password;
            egui::Grid::new("ssh_properties")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Host");
                    ui.text_edit_singleline(&mut tool.ssh_host);
                    ui.end_row();
                    ui.label("User");
                    ui.text_edit_singleline(&mut tool.ssh_user);
                    ui.end_row();
                    ui.label("Port");
                    ui.add(egui::DragValue::new(&mut tool.ssh_port).range(0..=65535));
                    ui.end_row();
                    if tool.kind == ConfiguredToolKind::SshExec {
                        ui.label("Authentication");
                        egui::ComboBox::from_id_salt(("ssh_authentication", index))
                            .selected_text(ssh_authentication_label(&authentication))
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut authentication,
                                    SshAuthentication::Agent,
                                    "SSH agent",
                                );
                                ui.selectable_value(
                                    &mut authentication,
                                    SshAuthentication::IdentityFile,
                                    "Identity file / FIDO2 key",
                                );
                                ui.selectable_value(
                                    &mut authentication,
                                    SshAuthentication::Password,
                                    "Password (russh session)",
                                );
                            });
                        ui.end_row();
                    } else {
                        ui.label("Authentication");
                        egui::ComboBox::from_id_salt(("ssh_authentication", index))
                            .selected_text(if use_agent {
                                "SSH agent"
                            } else {
                                "Identity file / FIDO2 key"
                            })
                            .show_ui(ui, |ui| {
                                ui.selectable_value(&mut use_agent, true, "SSH agent");
                                ui.selectable_value(
                                    &mut use_agent,
                                    false,
                                    "Identity file / FIDO2 key",
                                );
                            });
                        ui.end_row();
                    }
                    if password_auth {
                        ui.label("Host fingerprint");
                        ui.text_edit_singleline(&mut tool.ssh_host_fingerprint);
                        ui.end_row();
                        ui.label("Access lifetime (seconds)");
                        ui.add(egui::DragValue::new(&mut tool.ssh_session_seconds).range(1..=3600));
                        ui.end_row();
                    }
                });
            tool.ssh_authentication = authentication;
            if password_auth {
                ui.add_space(8.0);
                ui.group(|ui| {
                    ui.heading("Temporary SSH access");
                    ui.small("Enter the password here to open the configured russh session. It is never saved in the tool configuration.");
                    ui.horizontal(|ui| {
                        ui.label("Password");
                        ui.add(
                            egui::TextEdit::singleline(&mut self.ssh_password_draft)
                                .password(true)
                                .hint_text("enter password for this session"),
                        );
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Connect for lifetime").clicked() {
                            connect_password = true;
                        }
                        if ui.button("Revoke access").clicked() {
                            revoke_password = true;
                        }
                    });
                });
                ui.small("The server pins the host key, authenticates once, keeps the russh session in memory, and closes it automatically when this lifetime ends.");
            } else if use_agent {
                tool.ssh_identity_file.clear();
                ui.small("Recommended: use the local SSH agent. The private key stays outside this application; load it with ssh-add and use a short lifetime or confirmation mode.");
            } else {
                ui.label("Identity file or FIDO2 key path");
                ui.text_edit_singleline(&mut tool.ssh_identity_file);
                ui.colored_label(
                    egui::Color32::YELLOW,
                    "The path is saved in the configuration. The private key is never copied, but an unencrypted key file can be used by anyone who reads it. Prefer SSH agent or a hardware-backed FIDO2 key.",
                );
            }
            if password_auth {
                ui.small("Password sessions use the pinned SHA-256 fingerprint above; they do not consult known_hosts.");
            } else {
                ui.small("Remote calls use batch mode, disable agent forwarding, disable TTY allocation, and require an existing known_hosts entry. New host keys are not accepted automatically.");
            }
        }

        if tool.kind == ConfiguredToolKind::ScpUpload {
            ui.add_space(8.0);
            egui::Grid::new("upload_properties")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Local source file");
                    ui.text_edit_singleline(&mut tool.upload_source);
                    ui.end_row();
                    ui.label("Destination parameter");
                    ui.text_edit_singleline(&mut tool.upload_destination_parameter);
                    ui.end_row();
                });
            ui.small("The source file is selected here; the LLM supplies the remote destination folder as the named parameter.");
        }

        if tool.kind == ConfiguredToolKind::Docker {
            ui.add_space(12.0);
            ui.label("Docker build settings");
            egui::Grid::new("docker_properties")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label("Dockerfile storage");
                    ui.monospace(&tool.dockerfile);
                    ui.end_row();
                    ui.label("Build context");
                    ui.text_edit_singleline(&mut tool.docker_context);
                    ui.end_row();
                });
            ui.label("Dockerfile content");
            ui.small("Paste or edit the Dockerfile. It is stored under the application data directory and written when you save the tool.");
            if let Some(content) = self.dockerfile_drafts.get_mut(&tool.name) {
                ui.add(
                    egui::TextEdit::multiline(content)
                        .desired_rows(14)
                        .desired_width(f32::INFINITY)
                        .code_editor(),
                );
            }
            ui.small("The image is built and then run when the MCP tool is called. Docker must be installed and available to the server process.");
            ui.label("Secrets passed into the container");
            ui.small("Add names from the environment file. Values stay in the server environment and are passed with Docker's --env KEY form.");
            let mut remove_env = None;
            for (environment_index, environment_name) in tool.docker_env.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(environment_name);
                    if ui.button("Remove").clicked() {
                        remove_env = Some(environment_index);
                    }
                });
            }
            if let Some(environment_index) = remove_env {
                tool.docker_env.remove(environment_index);
                self.restart_required = true;
            }
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.docker_env_draft);
                if ui.button("Add secret variable").clicked() {
                    let name = self.docker_env_draft.trim().to_string();
                    if is_valid_env_key(&name) && !tool.docker_env.contains(&name) {
                        tool.docker_env.push(name);
                        self.docker_env_draft.clear();
                        self.restart_required = true;
                    }
                }
            });
        }

        ui.add_space(14.0);
        ui.heading("Parameters supplied by the LLM");
        ui.small("Required parameters appear in the generated MCP input schema. Values are inserted as individual command arguments.");
        let mut remove_parameter = None;
        for (parameter_index, parameter) in tool.parameters.iter_mut().enumerate() {
            egui::Frame::group(ui.style()).show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut parameter.name);
                    ui.label("Type");
                    egui::ComboBox::from_id_salt(("parameter_type", parameter_index))
                        .selected_text(&parameter.type_name)
                        .show_ui(ui, |ui| {
                            for type_name in ["string", "integer", "number", "boolean"] {
                                ui.selectable_value(
                                    &mut parameter.type_name,
                                    type_name.into(),
                                    type_name,
                                );
                            }
                        });
                    ui.checkbox(&mut parameter.required, "required");
                    if ui.button("Remove").clicked() {
                        remove_parameter = Some(parameter_index);
                    }
                });
                ui.add(
                    egui::TextEdit::singleline(&mut parameter.description)
                        .hint_text("Description shown to the LLM"),
                );
            });
        }
        if let Some(parameter_index) = remove_parameter {
            tool.parameters.remove(parameter_index);
        }
        if ui.button("Add parameter").clicked() {
            tool.parameters.push(ToolParameter {
                name: "value".into(),
                description: String::new(),
                type_name: "string".into(),
                required: true,
            });
        }

        ui.add_space(16.0);
        ui.horizontal(|ui| {
            if ui.button("Save changes").clicked() {
                save = true;
            }
            if ui.button("Delete tool").clicked() {
                delete = true;
            }
        });
        if *tool != original {
            self.restart_required = true;
        }
        let control_tool = tool.name.clone();
        if connect_password {
            self.connect_ssh_password(control_tool.clone());
        }
        if revoke_password {
            self.revoke_ssh_password(control_tool);
        }
        (save, delete)
    }
}

impl Drop for CommandMcpApp {
    fn drop(&mut self) {
        self.ssh_password_draft.zeroize();
        if let Err(error) = self.stop_server() {
            eprintln!("Could not stop the server while closing the UI: {error}");
        }
    }
}

impl CommandMcpApp {
    fn draw_error_banner(&mut self, ui: &mut egui::Ui) {
        let Some(message) = self.error_message.clone() else {
            return;
        };

        let mut dismiss = false;
        egui::Frame::group(ui.style())
            .fill(egui::Color32::from_rgb(74, 28, 28))
            .stroke(egui::Stroke::new(
                1.0,
                egui::Color32::from_rgb(220, 90, 90),
            ))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.colored_label(egui::Color32::from_rgb(255, 150, 150), "Error");
                    if ui.small_button("Copy").clicked() {
                        ui.ctx().copy_text(message.clone());
                    }
                    if ui.small_button("Dismiss").clicked() {
                        dismiss = true;
                    }
                });
                ui.add(
                    egui::Label::new(egui::RichText::new(message).color(
                        egui::Color32::from_rgb(255, 220, 220),
                    ))
                    .wrap(),
                );
            });

        if dismiss {
            self.error_message = None;
            self.status = "Error dismissed.".into();
        }
    }
}

impl eframe::App for CommandMcpApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_server();
        ui.horizontal(|ui| {
            ui.strong("Command MCP");
            ui.separator();
            if self.error_message.is_some() {
                ui.colored_label(egui::Color32::from_rgb(255, 120, 120), "Error");
            } else {
                ui.label(&self.status);
            }
            if self.server.is_none() && ui.button("Start").clicked() {
                match self.start_server() {
                    Ok(()) => {
                        self.restart_required = false;
                        let status = self.running_status();
                        self.set_status(status);
                    }
                    Err(error) => self.report_error("Could not start the server", error),
                }
            }
            if self.server.is_some() && ui.button("Stop").clicked() {
                if let Err(error) = self.stop_server() {
                    self.report_error("Could not stop the server", error);
                }
            }
            if ui.button("Restart").clicked() {
                if self.restart_required {
                    self.save_and_restart();
                } else {
                    self.restart_server();
                }
            }
            if ui.button("Save changes").clicked() {
                self.save_changes();
            }
            if self.restart_required {
                ui.colored_label(egui::Color32::YELLOW, "Restart required");
                if ui.button("Restart now").clicked() {
                    self.save_and_restart();
                }
            }
        });
        self.draw_error_banner(ui);
        ui.small(format!("Configuration: {}", self.config_path.display()));
        ui.separator();

        let mut save = false;
        let mut delete = false;
        ui.columns(2, |columns| {
            let ui = &mut columns[0];
            ui.heading("Tool catalog");
            ui.small("Built-in and configured tools exposed by the MCP server.");
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Default (all off)").clicked() {
                    self.config.enabled_commands = Some(default_enabled_commands());
                    self.restart_required = true;
                }
                if ui.button("Disable all").clicked() {
                    self.config.enabled_commands = Some(BTreeSet::new());
                    self.restart_required = true;
                }
            });
            ui.add_space(8.0);
            egui::ScrollArea::vertical()
                .id_salt("tool_catalog_scroll")
                .show(ui, |ui| {
                    if ui
                        .selectable_label(
                            self.selection == Some(Selection::Environment),
                            "⚙ Server and environment",
                        )
                        .clicked()
                    {
                        self.selection = Some(Selection::Environment);
                    }
                    ui.separator();
                    ui.label("Built-in command groups");
                    for group in COMMAND_GROUPS {
                        let enabled_count = group
                            .command_names
                            .iter()
                            .filter(|name| self.command_enabled(name))
                            .count();
                        let mut all_enabled = enabled_count == group.command_names.len();
                        let mut group_action = None;
                        let group_id = ui.make_persistent_id(("command_group", group.name));
                        let header =
                            egui::collapsing_header::CollapsingState::load_with_default_open(
                                ui.ctx(),
                                group_id,
                                false,
                            )
                            .show_header(ui, |ui| {
                                if ui.checkbox(&mut all_enabled, group.name).changed() {
                                    group_action = Some(all_enabled);
                                }
                                ui.small(format!(
                                    "{enabled_count}/{} enabled",
                                    group.command_names.len()
                                ));
                                if ui.small_button("All").clicked() {
                                    group_action = Some(true);
                                }
                                if ui.small_button("None").clicked() {
                                    group_action = Some(false);
                                }
                                ui.small(group.description);
                            });
                        if let Some(enabled) = group_action {
                            self.set_builtin_group_enabled(group, enabled);
                        }
                        header.body(|ui| {
                            for name in group.command_names {
                                let Some(spec) =
                                    COMMAND_SPECS.iter().find(|spec| spec.name == *name)
                                else {
                                    continue;
                                };
                                let enabled = self.command_enabled(spec.name);
                                let label =
                                    format!("{} {}", if enabled { "●" } else { "○" }, spec.name);
                                if ui
                                    .selectable_label(
                                        self.selection
                                            == Some(Selection::BuiltIn(spec.name.into())),
                                        label,
                                    )
                                    .clicked()
                                {
                                    self.selection = Some(Selection::BuiltIn(spec.name.into()));
                                }
                            }
                        });
                    }
                    ui.separator();
                    let mut configured_action = None;
                    ui.horizontal(|ui| {
                        ui.label("Configured tools");
                        if ui.button("+ New").clicked() {
                            self.add_tool();
                        }
                        if ui.button("+ SSH (password auth)").clicked() {
                            self.add_tool_kind(ConfiguredToolKind::SshExec);
                            if let Some(Selection::Configured(index)) = self.selection
                                && let Some(tool) = self.config.tools.get_mut(index)
                            {
                                tool.ssh_authentication = SshAuthentication::Password;
                            }
                        }
                        if ui.button("+ Docker").clicked() {
                            self.add_tool_kind(ConfiguredToolKind::Docker);
                        }
                        if ui.small_button("All").clicked() {
                            configured_action = Some(true);
                        }
                        if ui.small_button("None").clicked() {
                            configured_action = Some(false);
                        }
                    });
                    if let Some(enabled) = configured_action {
                        self.set_configured_tools_enabled(enabled);
                    }
                    for (index, tool) in self.config.tools.iter().enumerate() {
                        let label = format!(
                            "{} {}",
                            if tool.enabled { "●" } else { "○" },
                            if tool.name.is_empty() {
                                "(unnamed)"
                            } else {
                                &tool.name
                            }
                        );
                        if ui
                            .selectable_label(
                                self.selection == Some(Selection::Configured(index)),
                                label,
                            )
                            .clicked()
                        {
                            self.selection = Some(Selection::Configured(index));
                        }
                    }
                });
            let ui = &mut columns[1];
            egui::ScrollArea::vertical().show(ui, |ui| match self.selection.clone() {
                Some(Selection::Environment) => self.draw_environment_editor(ui),
                Some(Selection::BuiltIn(name)) => self.draw_builtin_editor(ui, &name),
                Some(Selection::Configured(index)) => {
                    (save, delete) = self.draw_tool_editor(ui, index);
                }
                None => {
                    ui.heading("Select a tool");
                    ui.label(
                        "Choose a built-in command or create a configured tool from the catalog.",
                    );
                }
            });
        });

        if delete
            && let Some(Selection::Configured(index)) = self.selection.take()
            && index < self.config.tools.len()
        {
            self.config.tools.remove(index);
            self.save_and_restart();
        }
        if save {
            self.save_changes();
        }
    }
}

fn kind_label(kind: &ConfiguredToolKind) -> &'static str {
    match kind {
        ConfiguredToolKind::Local => "Local command",
        ConfiguredToolKind::SshExec => "SSH command",
        ConfiguredToolKind::LegacySshPassword => "Legacy SSH password tool",
        ConfiguredToolKind::ScpUpload => "SCP file upload",
        ConfiguredToolKind::Docker => "Dockerfile command",
    }
}

fn ssh_authentication_label(authentication: &SshAuthentication) -> &'static str {
    match authentication {
        SshAuthentication::Agent => "SSH agent",
        SshAuthentication::IdentityFile => "Identity file / FIDO2 key",
        SshAuthentication::Password => "Password (russh session)",
    }
}

fn is_valid_env_key(key: &str) -> bool {
    let mut characters = key.chars();
    matches!(characters.next(), Some(first) if first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("key")
        || key.contains("secret")
        || key.contains("token")
        || key.contains("password")
        || key.contains("passwd")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        env,
        ffi::OsString,
        fs,
        sync::{Mutex, OnceLock},
        thread,
        time::Duration,
    };

    fn environment_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    struct TestEnvironment {
        previous: Vec<(String, Option<OsString>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl TestEnvironment {
        fn new(values: &[(&str, &str)]) -> Self {
            let lock = environment_lock();
            let previous = values
                .iter()
                .map(|(key, value)| {
                    let previous = env::var_os(key);
                    unsafe { env::set_var(key, value) };
                    ((*key).into(), previous)
                })
                .collect();
            Self {
                previous,
                _lock: lock,
            }
        }
    }

    impl Drop for TestEnvironment {
        fn drop(&mut self) {
            for (key, value) in &self.previous {
                unsafe {
                    match value {
                        Some(value) => env::set_var(key, value),
                        None => env::remove_var(key),
                    }
                }
            }
        }
    }

    fn test_path(label: &str, extension: &str) -> PathBuf {
        let suffix = format!(
            "{}-{}",
            std::process::id(),
            thread::current().name().unwrap_or("test")
        );
        env::temp_dir().join(format!("command-mcp-ui-{label}-{suffix}.{extension}"))
    }

    #[cfg(unix)]
    fn executable_script(label: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = test_path(label, "sh");
        fs::write(&path, body).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn test_app(config_path: PathBuf, env_path: PathBuf) -> CommandMcpApp {
        CommandMcpApp {
            config_path,
            config: CommandConfig::default(),
            selection: None,
            server: None,
            status: String::new(),
            error_message: None,
            env_path,
            env_values: BTreeMap::from([("COMMAND_MCP_API_KEY".into(), "test-key".into())]),
            reveal_secrets: false,
            restart_required: true,
            docker_env_draft: String::new(),
            dockerfile_drafts: BTreeMap::new(),
            new_env_key: String::new(),
            ssh_password_draft: String::new(),
            ssh_password_tool: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn restart_reports_a_server_that_exits_immediately() {
        let _environment_lock = environment_lock();
        let script_path = executable_script(
            "failure",
            "#!/bin/sh\necho server startup failure >&2\nexit 1\n",
        );
        let previous_binary = env::var_os("COMMAND_MCP_SERVER_BIN");
        unsafe {
            env::set_var("COMMAND_MCP_SERVER_BIN", &script_path);
        }

        let suffix = format!(
            "{}-{}",
            std::process::id(),
            thread::current().name().unwrap_or("test")
        );
        let config_path = env::temp_dir().join(format!("command-mcp-ui-{suffix}.toml"));
        let env_path = env::temp_dir().join(format!("command-mcp-ui-{suffix}.env"));
        let mut app = test_app(config_path.clone(), env_path.clone());

        app.save_and_restart();
        thread::sleep(Duration::from_millis(25));
        app.poll_server();

        assert!(app.server.is_none());
        assert!(app.restart_required);
        assert!(app.status.contains("Server exited"));
        assert!(app.status.contains("server startup failure"));

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(env_path);
        unsafe {
            match previous_binary {
                Some(value) => env::set_var("COMMAND_MCP_SERVER_BIN", value),
                None => env::remove_var("COMMAND_MCP_SERVER_BIN"),
            }
        }
        let _ = fs::remove_file(script_path);
    }

    #[cfg(unix)]
    #[test]
    fn server_stderr_is_drained_without_blocking_a_noisy_child() {
        let _environment_lock = environment_lock();
        let script_path = executable_script(
            "noisy-failure",
            "#!/bin/sh\ni=0\nwhile [ $i -lt 20000 ]; do\n  echo noisy-server-output-$i >&2\n  i=$((i + 1))\ndone\nexit 1\n",
        );
        let previous_binary = env::var_os("COMMAND_MCP_SERVER_BIN");
        unsafe { env::set_var("COMMAND_MCP_SERVER_BIN", &script_path) };
        let mut app = test_app(
            test_path("noisy-failure", "toml"),
            test_path("noisy-failure", "env"),
        );

        app.restart_server();
        for _ in 0..100 {
            app.poll_server();
            if app.server.is_none() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert!(app.server.is_none());
        assert!(app.status.contains("Server exited"));
        assert!(app.status.contains("noisy-server-output-19999"));

        unsafe {
            match previous_binary {
                Some(value) => env::set_var("COMMAND_MCP_SERVER_BIN", value),
                None => env::remove_var("COMMAND_MCP_SERVER_BIN"),
            }
        }
        let _ = fs::remove_file(script_path);
    }

    #[cfg(unix)]
    #[test]
    fn restarting_a_running_server_replaces_the_child_process() {
        let _environment_lock = environment_lock();
        let script_path = executable_script("long-running", "#!/bin/sh\nexec sleep 2\n");
        let previous_binary = env::var_os("COMMAND_MCP_SERVER_BIN");
        unsafe { env::set_var("COMMAND_MCP_SERVER_BIN", &script_path) };
        let mut app = test_app(
            test_path("long-running", "toml"),
            test_path("long-running", "env"),
        );

        app.restart_server();
        let first_pid = app.server.as_ref().map(ServerProcess::id).unwrap();
        assert!(app.status.contains("Server running"));
        app.restart_server();
        let second_pid = app.server.as_ref().map(ServerProcess::id).unwrap();

        assert_ne!(first_pid, second_pid);
        assert!(app.status.contains("Server running"));

        app.stop_server().unwrap();
        unsafe {
            match previous_binary {
                Some(value) => env::set_var("COMMAND_MCP_SERVER_BIN", value),
                None => env::remove_var("COMMAND_MCP_SERVER_BIN"),
            }
        }
        let _ = fs::remove_file(script_path);
    }

    #[cfg(unix)]
    #[test]
    fn fresh_ui_start_loads_saved_configuration_and_environment() {
        let script_path = executable_script("fresh-start", "#!/bin/sh\nexec sleep 2\n");
        let config_path = test_path("fresh-start", "toml");
        let env_path = test_path("fresh-start", "env");
        save_command_config(
            &config_path,
            &BTreeSet::new(),
            &[],
            &command_mcp::ServerConfig {
                host: "127.0.0.1".into(),
                port: 18055,
                auth_enabled: true,
                env_file: env_path.display().to_string(),
                allow_unauthenticated_remote: false,
            },
        )
        .unwrap();
        save_env_file(
            &env_path,
            &BTreeMap::from([(
                String::from("COMMAND_MCP_API_KEY"),
                String::from("saved-key"),
            )]),
        )
        .unwrap();
        let script_value = script_path.display().to_string();
        let config_value = config_path.display().to_string();
        let env_value = env_path.display().to_string();
        let _environment = TestEnvironment::new(&[
            ("COMMAND_MCP_SERVER_BIN", &script_value),
            ("COMMAND_MCP_CONFIG", &config_value),
            ("COMMAND_MCP_ENV_FILE", &env_value),
        ]);

        let mut app = CommandMcpApp::new();

        assert!(app.server.is_some());
        assert!(
            app.status
                .contains("Server running at http://127.0.0.1:18055/mcp")
        );
        assert_eq!(app.env_values["COMMAND_MCP_API_KEY"], "saved-key");
        app.stop_server().unwrap();

        let _ = fs::remove_file(script_path);
        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(env_path);
    }

    #[test]
    fn startup_reports_invalid_configuration_in_the_ui_status() {
        let config_path = test_path("invalid-config", "toml");
        let env_path = test_path("invalid-config", "env");
        fs::write(&config_path, "[server\ninvalid").unwrap();
        let config_value = config_path.display().to_string();
        let env_value = env_path.display().to_string();
        let _environment = TestEnvironment::new(&[
            ("COMMAND_MCP_CONFIG", &config_value),
            ("COMMAND_MCP_ENV_FILE", &env_value),
            ("COMMAND_MCP_SERVER_BIN", "/bin/false"),
        ]);

        let app = CommandMcpApp::new();

        assert!(app.status.contains("Startup errors:"));
        assert!(app.status.contains("Could not load configuration"));
        assert!(app.status.contains("Server status:"));

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(env_path);
    }

    #[test]
    fn startup_reports_environment_file_errors_in_the_ui_status() {
        let config_path = test_path("environment-error", "toml");
        let env_path = test_path("environment-error", "env");
        fs::create_dir(&env_path).unwrap();
        save_command_config(
            &config_path,
            &BTreeSet::new(),
            &[],
            &command_mcp::ServerConfig {
                host: "127.0.0.1".into(),
                port: 8000,
                auth_enabled: true,
                env_file: env_path.display().to_string(),
                allow_unauthenticated_remote: false,
            },
        )
        .unwrap();
        let config_value = config_path.display().to_string();
        let env_value = env_path.display().to_string();
        let _environment = TestEnvironment::new(&[
            ("COMMAND_MCP_CONFIG", &config_value),
            ("COMMAND_MCP_ENV_FILE", &env_value),
            ("COMMAND_MCP_SERVER_BIN", "/bin/false"),
        ]);

        let app = CommandMcpApp::new();

        assert!(app.status.contains("Could not load environment file"));
        assert!(app.status.contains("Could not create an API password"));

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_dir(env_path);
    }

    #[cfg(unix)]
    #[test]
    fn startup_reports_server_start_errors_in_the_ui_status() {
        use std::os::unix::fs::PermissionsExt;

        let binary = test_path("startup-not-executable", "bin");
        let config_path = test_path("startup-error", "toml");
        let env_path = test_path("startup-error", "env");
        fs::write(&binary, "not executable").unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&binary, permissions).unwrap();
        let binary_value = binary.display().to_string();
        let config_value = config_path.display().to_string();
        let env_value = env_path.display().to_string();
        let _environment = TestEnvironment::new(&[
            ("COMMAND_MCP_SERVER_BIN", &binary_value),
            ("COMMAND_MCP_CONFIG", &config_value),
            ("COMMAND_MCP_ENV_FILE", &env_value),
        ]);

        let app = CommandMcpApp::new();

        assert!(app.status.contains("Startup errors:"));
        assert!(app.status.contains("Could not start"));

        let _ = fs::remove_file(binary);
        let _ = fs::remove_file(env_path);
    }

    #[test]
    fn save_errors_are_reported_in_the_ui_status() {
        let config_path = test_path("save-error", "toml");
        let env_path = test_path("save-error", "env");
        fs::create_dir(&config_path).unwrap();
        let mut app = test_app(config_path.clone(), env_path.clone());

        app.save_changes();

        assert!(app.status.contains("Could not save changes"));
        assert!(app.status.contains("Is a directory"));

        let _ = fs::remove_dir(config_path);
        let _ = fs::remove_file(env_path);
    }

    #[test]
    fn invalid_tool_configuration_is_reported_before_writing() {
        let config_path = test_path("invalid-tool-save", "toml");
        let env_path = test_path("invalid-tool-save", "env");
        let mut app = test_app(config_path.clone(), env_path.clone());
        app.config.tools.push(ConfiguredTool {
            name: "invalid tool name".into(),
            enabled: true,
            ..ConfiguredTool::default()
        });

        app.save_changes();

        assert!(app.status.contains("tool configuration is invalid"));
        assert!(!config_path.exists());
        let _ = fs::remove_file(env_path);
    }

    #[cfg(unix)]
    #[test]
    fn asynchronous_server_control_errors_are_shown_in_the_ui_status() {
        let _environment_lock = environment_lock();
        let script_path = executable_script(
            "control-error",
            "#!/bin/sh\nprintf '%s\\n' '{\"event\":\"error\",\"tool\":\"maintenance\",\"message\":\"authentication failed\"}'\nsleep 2\n",
        );
        let previous_binary = env::var_os("COMMAND_MCP_SERVER_BIN");
        unsafe { env::set_var("COMMAND_MCP_SERVER_BIN", &script_path) };
        let mut app = test_app(
            test_path("control-error", "toml"),
            test_path("control-error", "env"),
        );

        app.restart_server();
        for _ in 0..100 {
            app.poll_server();
            if app.status.contains("authentication failed") {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }

        assert!(app.status.contains("SSH tool \"maintenance\" failed"));
        assert!(app.status.contains("authentication failed"));
        app.stop_server().unwrap();
        unsafe {
            match previous_binary {
                Some(value) => env::set_var("COMMAND_MCP_SERVER_BIN", value),
                None => env::remove_var("COMMAND_MCP_SERVER_BIN"),
            }
        }
        let _ = fs::remove_file(script_path);
    }

    #[test]
    fn saved_ui_changes_can_be_loaded_by_a_fresh_ui_instance() {
        let config_path = test_path("save-reload", "toml");
        let env_path = test_path("save-reload", "env");
        let mut app = test_app(config_path.clone(), env_path.clone());
        app.config.server.auth_enabled = false;
        app.config.server.host = "127.0.0.1".into();
        app.config.server.port = 18056;
        app.env_values.clear();
        app.config.tools.push(ConfiguredTool {
            name: "saved_tool".into(),
            enabled: true,
            ..ConfiguredTool::default()
        });

        app.save_changes();

        let saved_config = load_command_config(&config_path).unwrap();
        let saved_env = load_env_file(&env_path).unwrap();
        assert_eq!(saved_config.server.port, 18056);
        assert_eq!(saved_config.tools[0].name, "saved_tool");
        assert!(saved_config.tools[0].enabled);
        assert!(saved_env.is_empty());

        let _ = fs::remove_file(config_path);
        let _ = fs::remove_file(env_path);
    }

    #[cfg(unix)]
    #[test]
    fn server_start_errors_are_reported_in_the_ui_status() {
        use std::os::unix::fs::PermissionsExt;

        let binary = test_path("not-executable", "bin");
        fs::write(&binary, "not executable").unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&binary, permissions).unwrap();
        let binary_value = binary.display().to_string();
        let _environment = TestEnvironment::new(&[("COMMAND_MCP_SERVER_BIN", &binary_value)]);
        let mut app = test_app(
            test_path("start-error", "toml"),
            test_path("start-error", "env"),
        );

        app.restart_server();

        assert!(app.status.contains("Could not start the server"));
        assert!(app.restart_required);

        let _ = fs::remove_file(binary);
    }

    #[test]
    fn server_build_errors_are_reported_in_the_ui_status() {
        let _environment = TestEnvironment::new(&[
            (
                "COMMAND_MCP_SERVER_BIN",
                "/tmp/command-mcp-ui-missing-server",
            ),
            ("PATH", ""),
        ]);
        let mut app = test_app(
            test_path("build-error", "toml"),
            test_path("build-error", "env"),
        );

        app.restart_server();

        assert!(app.status.contains("Could not start the server"));
        assert!(app.status.contains("Could not build the server binary"));
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1120.0, 780.0]),
        ..Default::default()
    };
    let result = eframe::run_native(
        "Command MCP",
        options,
        Box::new(|_creation_context| Ok(Box::new(CommandMcpApp::new()))),
    );
    if let Err(error) = &result {
        eprintln!("Command MCP UI failed to start: {error}");
    }
    result
}
