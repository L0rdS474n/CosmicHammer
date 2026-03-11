mod args;
mod commands;
mod logging;
mod signals;

use clap::Parser;

use args::{Cli, Commands};
use logging::init_logging;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logging();

    match cli.command.unwrap_or_else(Commands::default_run) {
        Commands::Run {
            report_window,
            report_url,
            altitude,
            interval,
            threads,
            pte_model,
            no_tui,
            arena_size,
        } => {
            commands::run::execute(
                &report_window,
                report_url.as_deref(),
                altitude,
                interval,
                threads,
                &pte_model,
                no_tui,
                arena_size,
            )?;
        }
        Commands::Syscheck => {
            commands::syscheck::execute()?;
        }
        Commands::Report { file } => {
            commands::report::execute(&file)?;
        }
        Commands::Inject => {
            commands::inject::execute()?;
        }
    }

    Ok(())
}
