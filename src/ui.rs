use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

use command_mcp::{
    COMMAND_SPECS, CommandConfig, ConfiguredTool, ConfiguredToolKind, ToolParameter,
    command_config_path, default_enabled_commands, ensure_env_api_key, env_file_path,
    load_command_config, load_env_file, save_command_config, save_env_file,
};

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
    server: Option<Child>,
    status: String,
    env_path: PathBuf,
    env_values: BTreeMap<String, String>,
    reveal_secrets: bool,
    restart_required: bool,
    docker_env_draft: String,
    new_env_key: String,
}

impl CommandMcpApp {
    fn new() -> Self {
        let config_path = command_config_path();
        let mut config = load_command_config(&config_path).unwrap_or_default();
        if config.enabled_commands.is_none() {
            config.enabled_commands = Some(default_enabled_commands());
        }
        let env_path = env_file_path(&config);
        let mut env_values = load_env_file(&env_path).unwrap_or_default();
        if config.server.auth_enabled
            && env_values
                .get("COMMAND_MCP_API_KEY")
                .is_none_or(String::is_empty)
            && let Ok(key) = ensure_env_api_key(&env_path)
        {
            env_values.insert("COMMAND_MCP_API_KEY".into(), key);
        }
        let mut app = Self {
            config_path,
            config,
            selection: None,
            server: None,
            status: "Starting the local MCP server…".into(),
            env_path,
            env_values,
            reveal_secrets: false,
            restart_required: false,
            docker_env_draft: String::new(),
            new_env_key: String::new(),
        };
        app.start_server();
        app
    }

    fn enabled_commands(&mut self) -> &mut BTreeSet<String> {
        self.config
            .enabled_commands
            .get_or_insert_with(default_enabled_commands)
    }

    fn persist_changes(&mut self) -> Result<(), String> {
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

    fn save_changes(&mut self) {
        match self.persist_changes() {
            Ok(()) => {
                self.restart_required = true;
                self.status = "Changes saved. Restart required to apply them.".into();
            }
            Err(error) => self.status = error,
        }
    }

    fn save_and_restart(&mut self) {
        if let Err(error) = self.persist_changes() {
            self.status = error;
            return;
        }
        self.restart_server();
        self.restart_required = false;
    }

    fn server_binary() -> PathBuf {
        if let Some(path) = env::var_os("COMMAND_MCP_SERVER_BIN") {
            return PathBuf::from(path);
        }
        let mut path = env::current_exe().unwrap_or_else(|_| PathBuf::from("command-mcp-ui"));
        path.set_file_name(if cfg!(windows) {
            "command-mcp.exe"
        } else {
            "command-mcp"
        });
        path
    }

    fn start_server(&mut self) {
        if self.server.is_some() {
            return;
        }
        let binary = Self::server_binary();
        if !binary.is_file() {
            let build = Command::new("cargo")
                .args(["build", "--quiet", "--bin", "command-mcp"])
                .status();
            if !build.map(|status| status.success()).unwrap_or(false) || !binary.is_file() {
                self.status = format!(
                    "The server binary {} is missing and could not be built. Set COMMAND_MCP_SERVER_BIN to a server executable.",
                    binary.display()
                );
                return;
            }
        }
        let result = Command::new(&binary)
            .arg("server")
            .env("COMMAND_MCP_CONFIG", &self.config_path)
            .env("COMMAND_MCP_ENV_FILE", &self.env_path)
            .env("COMMAND_MCP_HOST", &self.config.server.host)
            .env("COMMAND_MCP_PORT", self.config.server.port.to_string())
            .env(
                "COMMAND_MCP_AUTH_ENABLED",
                self.config.server.auth_enabled.to_string(),
            )
            .env(
                "COMMAND_MCP_ALLOW_UNAUTHENTICATED_REMOTE",
                self.config.server.allow_unauthenticated_remote.to_string(),
            )
            .env(
                "COMMAND_MCP_API_KEY",
                self.env_values
                    .get("COMMAND_MCP_API_KEY")
                    .cloned()
                    .unwrap_or_default(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        match result {
            Ok(child) => {
                self.server = Some(child);
                self.status = format!(
                    "Server running at http://{}:{}/mcp",
                    self.config.server.host, self.config.server.port
                );
            }
            Err(error) => {
                self.status = format!(
                    "Could not start {}: {error}. Set COMMAND_MCP_SERVER_BIN to the server executable.",
                    binary.display()
                );
            }
        }
    }

    fn stop_server(&mut self) {
        if let Some(mut child) = self.server.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.status = "Server stopped.".into();
    }

    fn restart_server(&mut self) {
        self.stop_server();
        self.start_server();
    }

    fn poll_server(&mut self) {
        let exited = self
            .server
            .as_mut()
            .and_then(|child| child.try_wait().ok().flatten())
            .is_some();
        if exited {
            self.server = None;
            self.status = "Server exited. Use Start or Restart to launch it again.".into();
        }
    }

    fn add_tool(&mut self) {
        let mut tool = ConfiguredTool::default();
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
                            self.status =
                                "Environment file loaded. Save changes, then restart the server."
                                    .into();
                            self.restart_required = true;
                        }
                        Err(error) => self.status = error,
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
                    self.status = "Environment variable names may contain only letters, digits, and underscores, and cannot start with a digit.".into();
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
        if index >= self.config.tools.len() {
            return (save, delete);
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
                    ui.label("Identity file");
                    ui.text_edit_singleline(&mut tool.ssh_identity_file);
                    ui.end_row();
                });
            ui.small("SSH authentication uses the configured identity file or the local SSH agent. No passwords are stored by this application.");
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
                    ui.label("Dockerfile");
                    ui.text_edit_singleline(&mut tool.dockerfile);
                    ui.end_row();
                    ui.label("Build context");
                    ui.text_edit_singleline(&mut tool.docker_context);
                    ui.end_row();
                });
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
        (save, delete)
    }
}

impl Drop for CommandMcpApp {
    fn drop(&mut self) {
        self.stop_server();
    }
}

impl eframe::App for CommandMcpApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_server();
        ui.horizontal(|ui| {
            ui.strong("Command MCP");
            ui.separator();
            ui.label(&self.status);
            if self.server.is_none() && ui.button("Start").clicked() {
                self.start_server();
            }
            if self.server.is_some() && ui.button("Stop").clicked() {
                self.stop_server();
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
                if ui.button("Safe defaults").clicked() {
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
                    ui.label("Built-in commands");
                    for spec in COMMAND_SPECS {
                        let enabled = self
                            .config
                            .enabled_commands
                            .as_ref()
                            .is_some_and(|commands| commands.contains(spec.name));
                        let label = format!("{} {}", if enabled { "●" } else { "○" }, spec.name);
                        if ui
                            .selectable_label(
                                self.selection == Some(Selection::BuiltIn(spec.name.into())),
                                label,
                            )
                            .clicked()
                        {
                            self.selection = Some(Selection::BuiltIn(spec.name.into()));
                        }
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        ui.label("Configured tools");
                        if ui.button("+ New").clicked() {
                            self.add_tool();
                        }
                    });
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
        ConfiguredToolKind::ScpUpload => "SCP file upload",
        ConfiguredToolKind::Docker => "Dockerfile command",
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

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1120.0, 780.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Command MCP",
        options,
        Box::new(|_creation_context| Ok(Box::new(CommandMcpApp::new()))),
    )
}
