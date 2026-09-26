use std::{env, io::Write, process::ExitCode};

use eidolon_semantic_canary::{export_qualification_summary_json, qualify_held_out};

fn main() -> ExitCode {
    match parse_args(env::args().skip(1)) {
        Ok(Action::Help) => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        Ok(Action::Qualify) => {
            match qualify_held_out().and_then(|report| export_qualification_summary_json(&report)) {
                Ok(mut artifact) => {
                    artifact.push(b'\n');
                    if std::io::stdout().write_all(&artifact).is_ok() {
                        ExitCode::SUCCESS
                    } else {
                        eprintln!("error: failed to write qualification artifact");
                        ExitCode::FAILURE
                    }
                }
                Err(_) => {
                    eprintln!("error: semantic-canary qualification failed");
                    ExitCode::FAILURE
                }
            }
        }
        Err(()) => {
            eprintln!("error: this command accepts no arguments\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}

enum Action {
    Help,
    Qualify,
}

fn parse_args<I, S>(args: I) -> Result<Action, ()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter();
    match args.next() {
        None => Ok(Action::Qualify),
        Some(argument) if matches!(argument.as_ref(), "-h" | "--help") && args.next().is_none() => {
            Ok(Action::Help)
        }
        Some(_) => Err(()),
    }
}

fn usage() -> &'static str {
    "Usage: eidolon-semantic-canary-qualify\n\nEmits the embedded held-out qualification summary as JSON.\nNo input files, network, tools, credentials, or runtime controls are used.\n"
}
