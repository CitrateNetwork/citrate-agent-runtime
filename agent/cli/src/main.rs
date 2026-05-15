//! `citrate-agent` CLI — RFC-CIT-AGENT-0001 §3.2.
//!
//! CIT-AGENT-7c lands the `doctor` subcommand. Future slices will
//! add `daemon`, `step`, `install` per the planset.

use clap::{Parser, Subcommand};

mod config;
mod doctor_cmd;

#[derive(Parser, Debug)]
#[command(name = "citrate-agent", version, about = "Citrate Agent CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the doctor pre-flight / continuous-monitoring pass.
    Doctor(doctor_cmd::DoctorArgs),
}

fn main() {
    let cli = Cli::parse();
    let exit = match cli.command {
        Command::Doctor(args) => {
            // The doctor pass + check set may use tokio internally
            // (AnchorReconciliationCheck async eth_call). Spin up a
            // multi-thread runtime to support block_in_place.
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("tokio runtime: {e}");
                    std::process::exit(2);
                }
            };
            rt.block_on(async { tokio::task::spawn_blocking(move || doctor_cmd::run(args)).await })
                .unwrap_or(2)
        }
    };
    std::process::exit(exit);
}
