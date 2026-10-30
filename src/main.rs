//! vmdk_tree_compact: dry-run analysis of reclaimable space in a VMware hosted-sparse VMDK
//! snapshot tree whose guest uses NTFS. Nothing under the VM directory is ever written:
//! every file is opened read-only and read with positioned reads.

mod analysis;
mod descriptor;
mod io;
mod layer;
mod ntfs;
mod partition;
mod report;
mod sparse;
mod tree;
mod view;

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
	/// Print per node: partitions, NTFS volume geometry, and total/free bytes according to $Bitmap.
	Ntfs {
		/// VM directory containing the .vmx, .vmsd and .vmdk files.
		dir: PathBuf,
	},
	/// Dry run: report reclaimable grains per layer (allocated grains that every node seeing them has free in NTFS).
	Analyze {
		/// VM directory containing the .vmx, .vmsd and .vmdk files.
		dir: PathBuf,
		/// Also read every allocated grain of every layer and count all-zero grains (reads all grain data).
		#[arg(long)]
		scan_zero: bool,
	},
}

/// Reads all grain data of every layer; progress goes to stderr.
fn scan_zero_all(t: &tree::Tree) -> Result<Vec<analysis::Bitset>> {
	let total: u64 = t.nodes.iter().map(|n| n.layer.data_grains * n.layer.grain_bytes()).sum();
	let start = std::time::Instant::now();
	let mut before = 0u64;
	let mut out = Vec::with_capacity(t.len());
	for node in &t.nodes {
		let mut last_report = 0u64;
		let z = analysis::scan_zero(&node.layer, &mut |done| {
			if done - last_report >= 1 << 30 {
				last_report = done;
				eprint!("\rscan-zero: {} / {} read ({})   ", report::size(before + done), report::size(total), node.layer.file_name);
			}
		})?;
		before += node.layer.data_grains * node.layer.grain_bytes();
		out.push(z);
	}
	eprintln!("\rscan-zero: {} read in {:.0} s{}", report::size(before), start.elapsed().as_secs_f64(), " ".repeat(30));
	Ok(out)
}

fn run(cli: Cli) -> Result<()> {
	match cli.command {
		Command::Tree { dir } => {
			let t = tree::Tree::load(&dir)?;
			print!("{}", report::tree_report(&t));
		}
		Command::Ntfs { dir } => {
			let t = tree::Tree::load(&dir)?;
			let fs = ntfs::scan_tree(&t)?;
			print!("{}", report::ntfs_report(&t, &fs));
		}
		Command::Analyze { dir, scan_zero } => {
			let t = tree::Tree::load(&dir)?;
			let fs = ntfs::scan_tree(&t)?;
			let alloc: Vec<analysis::Bitset> = t.nodes.iter().map(|n| n.layer.alloc.clone()).collect();
			let free: Vec<analysis::Bitset> = fs.iter().map(|f| f.free.clone()).collect();
			let reclaim = analysis::analyze(&t.parents(), &t.children(), &alloc, &free)?;
			let zero = if scan_zero { Some(scan_zero_all(&t)?) } else { None };
			print!("{}", report::analyze_report(&t, &fs, &reclaim, zero.as_deref()));
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
