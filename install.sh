#!/usr/bin/env bash
set -euo pipefail

BOLD='\033[1m'
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
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
echo -e "${CYAN}[2/3]${RESET} Building WireHunt (release mode)..."
cargo build --release

# Install to cargo bin
echo -e "${CYAN}[3/3]${RESET} Installing binaries..."
cargo install --path crates/wirehunt-cli --force
cargo install --path crates/wirehunt-tui --force

echo ""
echo -e "${GREEN}${BOLD}WireHunt installed successfully!${RESET}"
echo ""
echo "  Binaries installed to: $(which wirehunt 2>/dev/null || echo '$HOME/.cargo/bin/')"
echo ""
echo "  Usage:"
echo "    wirehunt analyze capture.pcap --out case/ --profile ctf"
echo "    wirehunt-tui case/"
echo ""
echo "  Run 'wirehunt --help' for all commands."
