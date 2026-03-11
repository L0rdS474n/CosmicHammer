/// Run all system pre-flight checks and display the results.
pub fn execute() -> anyhow::Result<()> {
    let (results, _exit_code) = cosmic_hammer_syscheck::run_all_checks();
    cosmic_hammer_syscheck::print_results(&results);
    Ok(())
}
