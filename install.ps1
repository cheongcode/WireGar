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
Write-Host "All-in-one network forensic engine" -ForegroundColor Gray
Write-Host ""

# Check for Rust
$rustc = Get-Command rustc -ErrorAction SilentlyContinue
if (-not $rustc) {
    Write-Host "[1/3] Installing Rust toolchain..." -ForegroundColor Cyan
    # Try winget first, fall back to rustup-init
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        winget install Rustlang.Rustup --accept-source-agreements --accept-package-agreements
    } else {
        Write-Host "  Downloading rustup-init.exe..." -ForegroundColor Gray
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile "$env:TEMP\rustup-init.exe"
        & "$env:TEMP\rustup-init.exe" -y
    }
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    rustup default stable
} else {
    Write-Host "[1/3] Rust toolchain found: $(rustc --version)" -ForegroundColor Green
}

# Build
Write-Host "[2/3] Building WireHunt (release mode, this may take a few minutes)..." -ForegroundColor Cyan
cargo build --release

# Install
Write-Host "[3/3] Installing binaries to PATH..." -ForegroundColor Cyan
cargo install --path crates/wirehunt-cli --force 2>$null
cargo install --path crates/wirehunt-tui --force 2>$null

Write-Host ""
Write-Host "WireHunt installed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "  Quick Start:" -ForegroundColor White
Write-Host "    wirehunt serve                              " -ForegroundColor Cyan -NoNewline
Write-Host "# Launch web GUI at localhost:8888" -ForegroundColor Gray
Write-Host "    wirehunt analyze capture.pcap --out case/   " -ForegroundColor Cyan -NoNewline
Write-Host "# CLI analysis" -ForegroundColor Gray
Write-Host "    wirehunt-tui case/                          " -ForegroundColor Cyan -NoNewline
Write-Host "# Terminal UI" -ForegroundColor Gray
Write-Host ""
Write-Host "  Optional -- Threat Intelligence API Keys:" -ForegroundColor White
Write-Host "    `$env:VIRUSTOTAL_API_KEY = 'your-key'       " -ForegroundColor Yellow -NoNewline
Write-Host "# https://virustotal.com" -ForegroundColor Gray
Write-Host "    `$env:ABUSEIPDB_API_KEY = 'your-key'        " -ForegroundColor Yellow -NoNewline
Write-Host "# https://abuseipdb.com" -ForegroundColor Gray
Write-Host "    `$env:SHODAN_API_KEY = 'your-key'           " -ForegroundColor Yellow -NoNewline
Write-Host "# https://shodan.io" -ForegroundColor Gray
Write-Host "    (GeoIP and WHOIS work automatically, no keys needed)" -ForegroundColor Gray
Write-Host ""
Write-Host "  Run 'wirehunt --help' for all commands." -ForegroundColor Gray
