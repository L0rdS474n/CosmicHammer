use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cosmic-hammer",
    version = cosmic_hammer_core::VERSION,
    about = "Cosmic ray bit-flip detector"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the main scan loop (default)
    Run {
        /// Report window duration (e.g. "3d", "72h", "4320m")
        #[arg(long, default_value = "3d")]
        report_window: String,

        /// URL to POST reports to
        #[arg(long)]
        report_url: Option<String>,

        /// Altitude in metres (for cosmic ray rate estimation)
        #[arg(long)]
        altitude: Option<i32>,

        /// Scan interval in seconds
        #[arg(long, default_value_t = 5)]
        interval: u32,

        /// Number of scanner threads
        #[arg(long, default_value_t = 8)]
        threads: usize,

        /// PTE model: auto, x86_64, arm64, riscv-sv39
        #[arg(long, default_value = "auto")]
        pte_model: String,

        /// Disable TUI and print to stdout
        #[arg(long)]
        no_tui: bool,

        /// Arena size in MB
        #[arg(long, default_value_t = 512)]
        arena_size: usize,
    },

    /// Run system diagnostics
    Syscheck,

    /// View a saved report file
    Report {
        /// Path to the JSON report file
        #[arg(long)]
        file: String,
    },

    /// Inject a test flip for debugging
    Inject,
}

impl Commands {
    /// Return a `Run` variant with all defaults, used when no subcommand is provided.
    pub fn default_run() -> Self {
        Commands::Run {
            report_window: "3d".to_string(),
            report_url: None,
            altitude: None,
            interval: 5,
            threads: 8,
            pte_model: "auto".to_string(),
            no_tui: false,
            arena_size: 512,
        }
    }
}
