use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "cosmic-hammer",
    version = cosmic_hammer_core::VERSION,
    about = "Cosmic ray bit-flip detector",
    after_help = "Run 'cosmic-hammer run --help' for scan options including --report-url"
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

        /// URL to POST reports to [default if flag without value: cosmos.fuzzsociety.org:5000]
        #[arg(long, default_missing_value = cosmic_hammer_core::DEFAULT_REPORT_URL, num_args = 0..=1)]
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

        /// Play a retro sound when bit-flips are detected (requires flip-sound feature)
        #[arg(long)]
        flip_sound: bool,
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
    Inject {
        /// Play a retro sound when the injected flip is detected (requires flip-sound feature)
        #[arg(long)]
        flip_sound: bool,
    },
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
            flip_sound: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T6: Given the "run" subcommand with the --flip-sound flag, when the CLI is
    // parsed, then the flip_sound field inside Commands::Run is true.
    #[test]
    fn given_run_subcommand_with_flip_sound_flag_when_parsed_then_flip_sound_true() {
        let cli = Cli::try_parse_from(["cosmic-hammer", "run", "--flip-sound"])
            .expect("parsing should succeed");
        match cli.command.expect("command should be present") {
            Commands::Run { flip_sound, .. } => {
                assert!(flip_sound, "flip_sound must be true when --flip-sound is passed");
            }
            _ => panic!("expected Commands::Run"),
        }
    }

    // T7: Given the "run" subcommand without the --flip-sound flag, when the CLI
    // is parsed, then the flip_sound field inside Commands::Run is false (the default).
    #[test]
    fn given_run_subcommand_without_flip_sound_flag_when_parsed_then_flip_sound_false() {
        let cli = Cli::try_parse_from(["cosmic-hammer", "run"])
            .expect("parsing should succeed");
        match cli.command.expect("command should be present") {
            Commands::Run { flip_sound, .. } => {
                assert!(!flip_sound, "flip_sound must be false when --flip-sound is absent");
            }
            _ => panic!("expected Commands::Run"),
        }
    }

    // T8: Given the "inject" subcommand with the --flip-sound flag, when the CLI
    // is parsed, then the flip_sound field inside Commands::Inject is true.
    #[test]
    fn given_inject_subcommand_with_flip_sound_flag_when_parsed_then_flip_sound_true() {
        let cli = Cli::try_parse_from(["cosmic-hammer", "inject", "--flip-sound"])
            .expect("parsing should succeed");
        match cli.command.expect("command should be present") {
            Commands::Inject { flip_sound } => {
                assert!(flip_sound, "flip_sound must be true when --flip-sound is passed");
            }
            _ => panic!("expected Commands::Inject"),
        }
    }

    // T9: Given the "inject" subcommand without the --flip-sound flag, when the
    // CLI is parsed, then the flip_sound field inside Commands::Inject is false.
    #[test]
    fn given_inject_subcommand_without_flip_sound_flag_when_parsed_then_flip_sound_false() {
        let cli = Cli::try_parse_from(["cosmic-hammer", "inject"])
            .expect("parsing should succeed");
        match cli.command.expect("command should be present") {
            Commands::Inject { flip_sound } => {
                assert!(!flip_sound, "flip_sound must be false when --flip-sound is absent");
            }
            _ => panic!("expected Commands::Inject"),
        }
    }

    // T10: Given no subcommand is provided (CLI called with no args), when
    // Commands::default_run() is called, then flip_sound defaults to false.
    // This mirrors what main() does when cli.command is None.
    #[test]
    fn given_no_subcommand_when_default_run_called_then_flip_sound_is_false() {
        let cmd = Commands::default_run();
        match cmd {
            Commands::Run { flip_sound, .. } => {
                assert!(!flip_sound, "default_run must produce flip_sound = false");
            }
            _ => panic!("default_run must return Commands::Run"),
        }
    }
}
