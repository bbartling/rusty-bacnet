//! `bacnet tui` without a terminal: `bacnet tui > out.txt` must fail with a
//! hint on stderr and leave the output file empty. The support harness runs
//! the binary with stdin from /dev/null and stdout and stderr to files.
#[allow(dead_code)]
mod support;
use support::{failure, run};

#[cfg(feature = "tui")]
#[tokio::test]
async fn tui_without_a_terminal_fails_with_a_hint_and_writes_nothing() {
    for args in [
        vec!["tui"],
        vec!["--json", "tui", "--fps", "5"],
        vec!["--sc", "tui"],
    ] {
        let output = run(&args).await;
        failure(&output, "needs an interactive terminal");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("bacnet discover --json"), "{stderr}");
    }
}

#[cfg(not(feature = "tui"))]
#[tokio::test]
async fn tui_without_the_feature_preserves_its_rebuild_advice() {
    let output = run(["tui"]).await;
    failure(&output, "cargo install bacnet-cli --features tui");
}

#[tokio::test]
async fn tui_help_lists_its_flags() {
    let output = run(["tui", "--help"]).await;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(
        text.contains("--fps <FPS>") && text.contains("--log-file <FILE>"),
        "{text}"
    );
}
