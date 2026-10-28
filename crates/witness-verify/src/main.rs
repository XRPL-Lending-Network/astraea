//! Independent verification of an xrpl-witness archive, without us and
//! without a node.
//!
//! - `archive`: segment seals, the seal chain, the signature of every validation;
//! - `quorum`: whether each ledger is confirmed under a given trust policy;
//! - `export`: an evidence package for a single ledger;
//! - `evidence`: checking such a package without the archive, a node, or us.
//!
//! The result is JSON on stdout. Exit code 1 means something did not match,
//! 2 means the check could not be carried out.

mod archive;
mod evidence;
mod quorum;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Verify an xrpl-witness archive: seals, signatures, quorum"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Seals, the chain, and the signature of every validation.
    Archive(archive::ArchiveArgs),
    /// Quorum under a trust policy for a range of ledgers.
    Quorum(quorum::QuorumArgs),
    /// Build an evidence package for a single ledger.
    Export(evidence::ExportArgs),
    /// Check an evidence package against your own trust policy.
    Evidence(evidence::CheckArgs),
}

fn main() {
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Archive(a) => archive::run(a),
        Command::Quorum(q) => quorum::run(q),
        Command::Export(e) => evidence::export(e),
        Command::Evidence(c) => evidence::check(c),
    };
    match result {
        Ok(true) => {}
        Ok(false) => std::process::exit(1),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(2);
        }
    }
}
