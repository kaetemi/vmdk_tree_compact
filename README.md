# vmdk_tree_compact

Reclaim the space of deleted files from VMware virtual disks that sit in a snapshot tree.

VMware will not shrink a disk that has snapshots, and a snapshot's delta cannot be compacted
on its own because other snapshots may still depend on its blocks. This tool looks at the whole
tree at once: for every block in every layer it checks which snapshot states can still see
that block, reads the NTFS allocation bitmap as each of those states sees it, and drops the
block only when every one of them considers it free. Every snapshot still reads exactly the
same data afterwards; the only change is that free clusters may now read as zeros or as the
parent's stale content, which NTFS does not care about.

On the tree it was written for (a Windows XP guest, 40 GiB disk, 25 snapshots in a branching
tree, 107 GB on disk) it freed 18.6 GiB in under six minutes, with no snapshot deleted.

## Scope and what it was tested on

- VMware **hosted sparse** VMDK extents, the format Workstation, Player and Fusion write
  (`twoGbMaxExtentSparse`, also `monolithicSparse`). ESXi's SEsparse and VMFS formats are
  not supported.
- Uncompressed extents with the standard metadata layout, header version 1, 64 KiB grains.
  Compressed or streamed extents are refused.
- **NTFS** volumes in the guest, found through an MBR or GPT partition table. Other file
  systems and unpartitioned space are treated as fully in use, so they are never touched.
- Snapshots that restore disk state only. Memory snapshots can hold file system state that is
  not on disk; the tool checks that every node's NTFS log is clean, but cannot see inside a
  memory image.

It has been tested on exactly one setup: **VMware Workstation 26.0** on Windows 11, with a
**Windows XP SP3** guest on one NTFS partition with 4 KiB clusters. Anything else is untested.
The on-disk formats are documented and stable, and the checks are strict, but treat a first run
on a different setup as an experiment, with a backup.

## How it works

1. Parse the descriptors, build the tree from `parentCID` / `parentFileNameHint`, and check it
   against the `.vmsd` and `.vmx`. Load every extent's grain directory and tables. Validate
   everything: CID chains, identical geometry, primary and redundant grain tables equal, grain
   offsets inside the file and non-overlapping, clean shutdown flags, no lock files.
2. For every node, read the partition table and the NTFS boot sector, `$MFT` and `$Bitmap`
   through that node's chain view. Cross-check: every cluster referenced by an in-use MFT
   record must be marked used in `$Bitmap`.
3. For every layer L and every grain allocated in it, walk L's subtree carrying the set of
   grains overwritten by layers below L. The grain must stay if any node where it is still
   visible has it in use. Everything else is reclaimable. The result is checked against an
   independent formulation and against a simulated removal.
4. `compact` rewrites each layer's extents with the surviving grains only, keeping the header,
   CIDs and metadata layout. Each new extent is re-opened and verified against the original
   byte for byte before the original is replaced and deleted. Afterwards the whole tree is
   re-analysed and must report zero reclaimable grains and identical NTFS summaries.

The design is written up in `DESIGN.md`.

## Usage

Power the VM off first. Make a backup; `compact` deletes the original extents layer by layer
as soon as the replacement is verified, because keeping them all would need as much free space
as the whole tree.

```
vmdk_tree_compact tree    <vmdir>        # the snapshot tree and per-layer sizes
vmdk_tree_compact ntfs    <vmdir>        # per node: partitions, NTFS geometry, used/free
vmdk_tree_compact analyze <vmdir>        # dry run: reclaimable bytes per layer
vmdk_tree_compact compact <vmdir>        # prints the plan only
vmdk_tree_compact compact <vmdir> --yes  # rewrites and replaces the extents
```

`<vmdir>` is the directory holding the `.vmx`, `.vmsd` and `.vmdk` files.

`analyze --scan-zero` additionally reads every grain and counts the all-zero ones, which is
what VMware's own shrink would drop. `compact --layer <descriptor>` limits the rewrite to the
named layers, `--keep-originals` keeps every replaced extent as `<extent>.old`, and `--resume`
cleans up after an interrupted run (deletes `*.compact`, renames `*.old` back) before starting.
Without `--resume` the tool refuses to run while such leftovers exist.

Example output of `analyze`, abbreviated:

```
Layer                              Snapshot        Alloc grains  Allocated  Recl grains  Reclaimable  Recl %
athenaxp.vmdk                      Base SP3               27775    1.7 GiB         3166    197.9 MiB   11.4%
  athenaxp-000001.vmdk             Base USP4              68274    4.2 GiB        35752      2.2 GiB   52.4%
    athenaxp-000002.vmdk           Base Rollup            27566    1.7 GiB          221     13.8 MiB    0.8%
...
Total                                                   1746808  106.6 GiB       305300     18.6 GiB   17.5%
```

## Building

Plain `cargo build --release` works on any platform with Rust; the only dependencies are
`anyhow` and `clap`. The repository's `build.ps1` / `build.sh` run the build inside the
`ryzombuild_xplat_tools` Docker image from the Ryzom Core quick start (cargo-xwin), producing a
Windows MSVC and a static Linux musl binary; pass `test` to run the tests first.

GitHub Actions (`.github/workflows/ci.yml`) runs `cargo fmt --check`, the tests and a release build
on Ubuntu (static x86_64 musl) and Windows (x86_64 MSVC) for every push, and uploads each binary
with the README, license and design notes as a `.tar.gz` or `.zip` plus a SHA-256 file. Pushing a
`v*` tag attaches those packages to a GitHub release.

## Safety notes

- Every read is a positioned read on a file opened read-only; the only files ever written are
  `<extent>.compact` during a `compact --yes` run.
- The analysis is re-run inside `compact` right before writing; a saved result is never used.
- If anything fails mid-layer the tool stops, leaves the `.compact` and `.old` files in place,
  and prints which files are in which state and how to recover.
- After compacting, boot the VM and revert to a snapshot or two before deleting the backup.

## License

CC0 1.0 Universal. See `LICENSE`.
