# vmdk_tree_compact — design

Reclaim space from a VMware hosted-sparse VMDK snapshot tree by dropping grains that no
restorable state needs: a grain in layer L is reclaimable iff, at every node N in the subtree
rooted at L (L included) where the grain is still visible (no layer on the path L→N below L
overwrote it), the NTFS `$Bitmap` as seen at N marks every cluster covering the grain as free.

Phase 1 (this milestone) is a **dry run** only: analyze the tree and report reclaimable bytes
per layer. No file is ever written. Reads are read-only (open files read-only, positioned reads).

## Input

A VM directory (e.g. `C:\vmware\athenaxp`) holding:

- `*.vmdk` descriptors (text): `CID`, `parentCID`, `createType="twoGbMaxExtentSparse"` (also
  accept `monolithicSparse` where the descriptor is embedded in the extent file),
  `parentFileNameHint`, and `RW <sectors> SPARSE "<extent file>"` lines.
- `*-sNNN.vmdk` hosted sparse extents: magic `KDMV`, version 1, little-endian header
  (`SparseExtentHeader` from the VMware Virtual Disk Format 5.0 spec): flags, capacity,
  grainSize (sectors), descriptorOffset/Size, numGTEsPerGT, rgdOffset, gdOffset, overHead,
  uncleanShutdown, compressAlgorithm. Refuse compressed extents (flag bit 16 / compressAlgorithm
  != 0) for now. Grain table entry 0 = unallocated; 1 = "zero grain" in some versions (treat as
  allocated-but-zero, i.e. not consuming space but present: it masks the parent); otherwise a
  sector offset into the extent file.
- `*.vmsd`: snapshot tree with `snapshotN.uid/parent/displayName/disk0.fileName`.
- `*.vmx`: `ide0:0.fileName` (or scsi0:0 / sata0:0 / nvme0:0) naming the current live layer.

The tree is built from the descriptors (`parentFileNameHint` / `parentCID`), which are
authoritative; `.vmsd` supplies display names and the `.vmx` identifies the live leaf.
Every node is a restorable state (each layer is either a snapshot's disk state or the live
leaf), so every node participates in the free-space intersection.

Validate: parentCID of a child equals CID of its parent; all layers have identical geometry
(same extent list sizes, same grain size); capacity sum matches.

## Model

- Global grain index `g = sector / grain_size` across the whole virtual disk (extent sizes are
  multiples of the grain size; verify).
- Per layer: an allocation bitset over all grains (allocated = GTE != 0), plus per extent the
  grain table for reading grain data.
- Logical read at node N for sector range: walk N → root, first layer whose grain is allocated
  serves it; otherwise zeros.

## NTFS free map per node

For each node N, using the chain-view reader:

1. Parse the MBR; walk primary + extended partitions. Also recognise a GPT (protective MBR
   0xEE) and read GPT entries. For each partition, read the boot sector; it is NTFS if the OEM
   id is `NTFS    `.
2. From the NTFS boot sector: bytes/sector, sectors/cluster, total sectors, MFT LCN,
   clusters-per-MFT-record (negative → 2^|n| bytes).
3. Read MFT record 0, apply the update-sequence fixups, parse attributes, take the
   non-resident `$DATA` (type 0x80) run list of `$MFT` (base record suffices; the first run
   covers record 6). Read record 6 (`$Bitmap`), parse its `$DATA` run list, read the bitmap
   (bit set = cluster in use; LSB first).
4. Free sectors of the volume = sectors of clusters whose bit is clear and that lie within
   `total sectors`. Everything else on the disk (partition gaps, boot sectors, backup boot
   sector, non-NTFS partitions, bits beyond the bitmap) is treated as in use.
5. Grain `g` is free at N iff every sector in `[g*gs, (g+1)*gs)` is a free sector. Compute this
   directly from the cluster bitmap with offset math; do not materialise a per-sector bitmap.

Report per node: volumes found, cluster size, total/free bytes according to `$Bitmap`, so the
numbers can be cross-checked against what the guest shows.

## Reclaim analysis

For each layer L:

```
keep = ∅
dfs(N = L, masked = ∅):
    needed = alloc(L) & !masked
    keep |= needed & !free(N)
    for child C of N: dfs(C, masked | alloc(C))
reclaimable(L) = alloc(L) & !keep
```

Bitsets are ~82 KB for a 40 GiB disk at 64 KB grains, so this is cheap even for 26 layers.

Optional `--scan-zero`: additionally read every allocated grain of every layer and count grains
that are entirely zero (what VMware's own shrink would drop). Off by default (reads all data).

## Output (dry run)

A table per layer in tree order with indentation showing the hierarchy: layer file, snapshot
display name (or `<live>`), allocated grains → bytes, reclaimable grains → bytes, on-disk size
of the extents, and totals. Plus a per-node NTFS summary (volume offset, size, free). Exit code
non-zero on any parse failure; never guess.

## Code layout

Rust 2021, single binary crate `vmdk_tree_compact`. Dependencies: `anyhow`, `clap` (derive).
Modules: `descriptor`, `sparse`, `layer` (descriptor + extents → grain bitset + reads),
`tree` (vmsd/vmx + chain building), `view` (chain-view reader), `partition` (MBR/GPT),
`ntfs`, `analysis`, `compact` (phase 2 writer, verifier, swap, resume), `report`, `main`. Positioned reads via `FileExt::seek_read` (Windows)
and `FileExt::read_at` (Unix). `rustfmt.toml`: `hard_tabs = true`, `max_width = 160`,
`use_small_heuristics = "Max"`. Unit tests for the sparse header parser, descriptor parser,
NTFS fixups/run-list decoding, and the reclaim algorithm on a synthetic 3-layer tree.

## Build

Builds run in the `ryzombuild_xplat_tools` Docker image (cargo-xwin). `build.ps1` runs:

```
docker run --rm -v ryzombuild_xplat_tools_cargo:/usr/local/cargo/registry -v ryzombuild_xplat_tools_xwin:/root/.cache/cargo-xwin -e CARGO_TARGET_DIR=/mnt/src/target --mount "type=bind,source=<repo>,target=/mnt/src" --workdir /mnt/src ryzombuild_xplat_tools cargo xwin build --release --target x86_64-pc-windows-msvc
```

and the same with `cargo build --release --target x86_64-unknown-linux-musl`. Tests run in the
container with `cargo test` (host target). The Windows binary runs natively:
`target\x86_64-pc-windows-msvc\release\vmdk_tree_compact.exe analyze C:\vmware\athenaxp`.

## Later phases (not now)

`compact`: write a new extent set per layer keeping only surviving grains, CID/parentCID
unchanged, swap in with the VM powered off, verify every node still reads identically outside
the reclaimed grains.

# Phase 2 — `compact`

Rewrites each layer's sparse extents keeping only the grains the analysis says must stay.
Descriptors, `.vmsd`, `.vmx`, `.vmsn` are never touched; CID/parentCID stay as they are, so
VMware sees the same disk chain.

## Preconditions (checked, hard failures)

- No `*.lck` directory or file in the VM directory; `uncleanShutdown` clear in every extent.
- Analysis re-run in the same process right before writing (never from a saved result).
- Free space on the target volume ≥ the new size of the largest layer plus 1 GiB margin.
  The host has about 47 GiB free, so originals cannot all be kept: each layer is replaced as
  soon as it is verified. A full backup copy exists at `C:\vmware\athenaxp - Copy`.

## Per layer (in any order; each layer is independent because the reclaim set is a fixpoint)

1. Write every extent of the layer to `<extent>.compact` in the same directory: a hosted sparse
   extent with the **same header fields** (magic, version 1, flags, capacity, grainSize,
   descriptorOffset/Size = 0, numGTEsPerGT, rgdOffset, gdOffset, overHead) and the same
   metadata layout (redundant GD + GTs at `rgdOffset`, primary GD + GTs at `gdOffset`, data
   from `overHead`). Kept grains are copied in logical grain order, packed from `overHead`
   upward; GTEs for reclaimed and unallocated grains are 0. Grain directory entries keep the
   same relative layout as the original (all GTs present, in order). `uncleanShutdown` = 0.
   File length = `overHead` + kept grains × grainSize sectors, exactly like VMware's files.
   Write with buffered sequential I/O; flush and fsync before verifying.
2. Verify `<extent>.compact` by re-opening it with the normal reader (so it must pass every
   validation `tree` applies): the allocated set must equal `alloc(L) & !reclaim(L)` for that
   extent, every kept grain must be byte-identical to the original, and the header must match
   the original except `uncleanShutdown`.
3. Replace: rename `<extent>` → `<extent>.old`, rename `<extent>.compact` → `<extent>`, for all
   extents of the layer; then delete the `.old` files of this layer. `--keep-originals` keeps
   the `.old` files instead (only if space allows; the precondition then uses the whole
   tree's new size).
4. Print the layer's before/after sizes.

If anything fails mid-layer, stop: leave `.compact` and `.old` files in place and print exactly
which files are in which state, and how to recover (`.old` → original name). On startup, refuse
to run if any `.compact` or `.old` file exists in the directory, unless `--resume` is given, in
which case leftover `.compact` files are deleted and `.old` files are restored first.

## After all layers

- Re-run the full analysis on the compacted tree in the same process. It must report
  0 reclaimable grains (the simultaneous drop is a fixpoint: a grain L drops is free at every
  node that newly sees L's parent's copy), all NTFS checks must pass, and the per-node
  `$Bitmap` summaries must be identical to the ones from before compaction.
- Print the total bytes freed and the final tree table.

## Options

`compact <dir> [--yes] [--keep-originals] [--resume] [--layer <descriptor>]...`
Without `--yes` the command prints the plan (per-layer bytes to be freed, free space check)
and exits without writing. `--layer` restricts to the named layers (still requires the full
analysis of the tree).

## Tests

A synthetic end-to-end test: build a small 3-layer tree (tiny capacity, e.g. 64 grains of
64 KiB) as real files in a temp directory with a fake NTFS-free map injected (the analysis
takes bitsets, so the test can feed free maps directly), run the writer + verifier + replace
on it, re-open the tree, and check contents per node against the pre-compaction chain view
for every grain not free at that node. Also test the failure path: a corrupted `.compact`
must abort without touching originals.
