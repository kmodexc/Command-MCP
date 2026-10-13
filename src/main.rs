use clap::{Parser, Subcommand};
use command_mcp::{
    commands::{serve_http, serve_stdio},
    load_settings,
};

#[derive(Debug, Parser)]
#[command(name = "command-mcp", about = "Allowlist-first MCP command server")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Server {
        #[arg(long, help = "Use MCP stdio instead of Streamable HTTP")]
        stdio: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    let settings = load_settings().map_err(anyhow::Error::msg)?;
    match cli.command.unwrap_or(Command::Server { stdio: false }) {
        Command::Server { stdio: true } => serve_stdio(settings).await?,
        Command::Server { stdio: false } => serve_http(settings).await?,
    }
    Ok(())
}
