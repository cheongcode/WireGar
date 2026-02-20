$ErrorActionPreference = "Stop"

Write-Host @"

 ██╗    ██╗██╗██████╗ ███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
 ██║    ██║██║██╔══██╗██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
 ██║ █╗ ██║██║██████╔╝█████╗  ███████║██║   ██║██╔██╗ ██║   ██║
 ██║███╗██║██║██╔══██╗██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║
 ╚███╔███╔╝██║██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚████║   ██║
  ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝

"@ -ForegroundColor Cyan

Write-Host "WireHunt Installer" -ForegroundColor White
Write-Host ""

# Check for Rust
$rustc = Get-Command rustc -ErrorAction SilentlyContinue
if (-not $rustc) {
    Write-Host "[1/3] Installing Rust toolchain..." -ForegroundColor Cyan
    winget install Rustlang.Rustup --accept-source-agreements --accept-package-agreements
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    rustup default stable
} else {
    Write-Host "[1/3] Rust toolchain found: $(rustc --version)" -ForegroundColor Green
}

# Build
Write-Host "[2/3] Building WireHunt (release mode)..." -ForegroundColor Cyan
cargo build --release

# Install
Write-Host "[3/3] Installing binaries..." -ForegroundColor Cyan
cargo install --path crates/wirehunt-cli --force
cargo install --path crates/wirehunt-tui --force

Write-Host ""
Write-Host "WireHunt installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Usage:"
Write-Host "    wirehunt analyze capture.pcap --out case/ --profile ctf"
Write-Host "    wirehunt-tui case/"
Write-Host ""
Write-Host "  Run 'wirehunt --help' for all commands."
