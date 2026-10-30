//! vmdk_tree_compact: dry-run analysis of reclaimable space in a VMware hosted-sparse VMDK
//! snapshot tree whose guest uses NTFS. Nothing under the VM directory is ever written:
//! every file is opened read-only and read with positioned reads.

mod analysis;
mod descriptor;
mod io;
mod layer;
mod report;
mod sparse;
mod tree;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "vmdk_tree_compact", version, about = "Analyze reclaimable space in a VMware hosted-sparse VMDK snapshot tree (NTFS guests). Read-only.")]
struct Cli {
	#[command(subcommand)]
	command: Command,
}

#[derive(Subcommand)]
enum Command {
	/// Print the snapshot tree: layer file, snapshot name, CID, allocated grains and on-disk extent size.
	Tree {
		/// VM directory containing the .vmx, .vmsd and .vmdk files.
		dir: PathBuf,
	},
}

fn run(cli: Cli) -> Result<()> {
	match cli.command {
		Command::Tree { dir } => {
			let t = tree::Tree::load(&dir)?;
			print!("{}", report::tree_report(&t));
		}
	}
	Ok(())
}

fn main() -> ExitCode {
	let cli = Cli::parse();
	match run(cli) {
		Ok(()) => ExitCode::SUCCESS,
		Err(e) => {
			eprintln!("error: {e:#}");
			ExitCode::FAILURE
		}
	}
}
