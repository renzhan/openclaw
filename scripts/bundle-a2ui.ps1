# PowerShell version of bundle-a2ui.sh for Windows
$ErrorActionPreference = "Stop"

Write-Host "A2UI bundle check (Windows mode)..."

$ROOT_DIR = Split-Path -Parent $PSScriptRoot
$HASH_FILE = Join-Path $ROOT_DIR "src\canvas-host\a2ui\.bundle.hash"
$OUTPUT_FILE = Join-Path $ROOT_DIR "src\canvas-host\a2ui\a2ui.bundle.js"

# Check if bundle already exists
if (Test-Path $OUTPUT_FILE) {
    Write-Host "A2UI bundle exists; skipping."
    exit 0
}

# Create placeholder bundle
Write-Host "Creating placeholder A2UI bundle for Windows..."
$bundleDir = Split-Path $OUTPUT_FILE -Parent
if (-not (Test-Path $bundleDir)) {
    New-Item -ItemType Directory -Force -Path $bundleDir | Out-Null
}

@"
// Placeholder bundle for Windows development
// This file is auto-generated. Do not edit manually.
export default {};
"@ | Out-File -FilePath $OUTPUT_FILE -Encoding utf8

"placeholder-windows-dev" | Out-File -FilePath $HASH_FILE -Encoding utf8 -NoNewline

Write-Host "A2UI placeholder bundle created successfully."
exit 0
