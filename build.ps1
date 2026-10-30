# Builds vmdk_tree_compact in the ryzombuild_xplat_tools Docker image.
# Usage: .\build.ps1 [test]
#   test  also runs `cargo test` (host linux-gnu target) before the release builds.
# Windows PowerShell 5.1 compatible.
param([string]$Mode = "")

$repo = (Resolve-Path $PSScriptRoot).Path

function Invoke-ContainerCargo([string[]]$CargoArgs) {
	Write-Host ("==> " + ($CargoArgs -join " "))
	& docker run --rm -v ryzombuild_xplat_tools_cargo:/usr/local/cargo/registry -v ryzombuild_xplat_tools_xwin:/root/.cache/cargo-xwin -e CARGO_TARGET_DIR=/mnt/src/target --mount "type=bind,source=$repo,target=/mnt/src" --workdir /mnt/src ryzombuild_xplat_tools @CargoArgs
	if ($LASTEXITCODE -ne 0) {
		Write-Host ("FAILED (exit code " + $LASTEXITCODE + "): " + ($CargoArgs -join " "))
		exit $LASTEXITCODE
	}
}

if ($Mode -eq "test") {
	Invoke-ContainerCargo @("cargo", "test")
} elseif ($Mode -ne "") {
	Write-Host ("Unknown argument: " + $Mode + " (expected: test)")
	exit 2
}
Invoke-ContainerCargo @("cargo", "xwin", "build", "--release", "--target", "x86_64-pc-windows-msvc")
Invoke-ContainerCargo @("cargo", "build", "--release", "--target", "x86_64-unknown-linux-musl")
Write-Host "OK"
