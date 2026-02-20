#!/usr/bin/env bash
set -euo pipefail

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

echo -e "${CYAN}${BOLD}"
echo ' ██╗    ██╗██╗██████╗ ███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗'
echo ' ██║    ██║██║██╔══██╗██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝'
echo ' ██║ █╗ ██║██║██████╔╝█████╗  ███████║██║   ██║██╔██╗ ██║   ██║   '
echo ' ██║███╗██║██║██╔══██╗██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║   '
echo ' ╚███╔███╔╝██║██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚████║   ██║   '
echo '  ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝'
echo -e "${RESET}"
echo -e "${BOLD}WireHunt Installer${RESET}"
echo -e "All-in-one network forensic engine"
echo ""

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo -e "${CYAN}[1/3]${RESET} Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo -e "${GREEN}[1/3]${RESET} Rust toolchain found: $(rustc --version)"
fi

# Build
echo -e "${CYAN}[2/3]${RESET} Building WireHunt (release mode, this may take a few minutes)..."
cargo build --release

# Install to cargo bin
echo -e "${CYAN}[3/3]${RESET} Installing binaries to PATH..."
cargo install --path crates/wirehunt-cli --force 2>/dev/null
cargo install --path crates/wirehunt-tui --force 2>/dev/null

echo ""
echo -e "${GREEN}${BOLD}WireHunt installed successfully!${RESET}"
echo ""
echo -e "  ${BOLD}Quick Start:${RESET}"
echo -e "    ${CYAN}wirehunt serve${RESET}                              # Launch web GUI at localhost:8888"
echo -e "    ${CYAN}wirehunt analyze capture.pcap --out case/${RESET}   # CLI analysis"
echo -e "    ${CYAN}wirehunt-tui case/${RESET}                         # Terminal UI"
echo ""
echo -e "  ${BOLD}Optional -- Threat Intelligence API Keys:${RESET}"
echo -e "    ${YELLOW}export VIRUSTOTAL_API_KEY=\"your-key\"${RESET}     # https://virustotal.com"
echo -e "    ${YELLOW}export ABUSEIPDB_API_KEY=\"your-key\"${RESET}     # https://abuseipdb.com"
echo -e "    ${YELLOW}export SHODAN_API_KEY=\"your-key\"${RESET}        # https://shodan.io"
echo -e "    (GeoIP and WHOIS work automatically, no keys needed)"
echo ""
echo -e "  Run '${CYAN}wirehunt --help${RESET}' for all commands."
