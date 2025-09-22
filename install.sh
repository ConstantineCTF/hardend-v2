#!/bin/bash

# HARDEND Cyberpunk Installation Script
# "Wake the f*ck up, samurai. We have a system to secure."

set -e

# Colors for cyberpunk output
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Cyberpunk banner
print_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
    ██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗██████╗
    ██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║██╔══██╗
    ███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║██║  ██║
    ██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║██║  ██║
    ██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║██████╔╝
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═════╝

    ◢◤◢◤◢◤ NEURAL INTERFACE INSTALLATION PROTOCOL ◢◤◢◤◢◤
    ▓▓▓ Cyberpunk Linux Security Assessment Framework ▓▓▓
    ◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤
EOF
    echo -e "${NC}"
}

# Progress bar function
progress_bar() {
    local duration=$1
    local message=$2
    echo -ne "${CYAN}◢◤ $message${NC}"

    for ((i=0; i<=50; i++)); do
        sleep $(echo "$duration/50" | bc -l 2>/dev/null || echo "0.02")
        echo -ne "▓"
    done
    echo -e " ${GREEN}[COMPLETE]${NC}"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}◢◤ WARNING: Running as root - neural interface will have full system access${NC}"
        echo -e "${YELLOW}   Some security checks may be bypassed in root mode${NC}"
        sleep 2
    fi
}

# Check system requirements
check_requirements() {
    echo -e "${CYAN}◢◤ Checking neural interface requirements...${NC}"

    # Check Go installation
    if ! command -v go &> /dev/null; then
        echo -e "${RED}◢◤ FATAL: Go compiler not found${NC}"
        echo -e "${RED}   Install Go 1.21+ from https://golang.org/dl/${NC}"
        exit 1
    fi

    # Check Go version
    GO_VERSION=$(go version | grep -oP 'go\d+\.\d+' | grep -oP '\d+\.\d+')
    REQUIRED_VERSION="1.21"

    if [[ $(echo "$GO_VERSION >= $REQUIRED_VERSION" | bc -l 2>/dev/null || echo "0") -eq 0 ]]; then
        echo -e "${RED}◢◤ FATAL: Go version $GO_VERSION insufficient${NC}"
        echo -e "${RED}   Require Go $REQUIRED_VERSION or higher${NC}"
        exit 1
    fi

    echo -e "${GREEN}◢◤ Go $GO_VERSION detected - neural compiler ready${NC}"

    # Check system utilities
    local required_tools=("systemctl" "ss" "netstat" "ps" "find" "grep" "awk")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "${YELLOW}◢◤ WARNING: $tool not found - some scans may be limited${NC}"
        fi
    done
}

# Install dependencies
install_dependencies() {
    echo -e "${CYAN}◢◤ Installing neural interface dependencies...${NC}"

    # Update Go modules
    if [[ -f "go.mod" ]]; then
        progress_bar 2 "Downloading neural pathway modules"
        go mod download
    else
        echo -e "${RED}◢◤ ERROR: go.mod not found - run from project directory${NC}"
        exit 1
    fi

    # Install additional tools if available
    if command -v apt-get &> /dev/null; then
        echo -e "${CYAN}◢◤ Installing Debian/Ubuntu system tools...${NC}"
        sudo apt-get update -qq
        sudo apt-get install -qq -y net-tools procps systemd coreutils findutils grep gawk bc
    elif command -v yum &> /dev/null; then
        echo -e "${CYAN}◢◤ Installing RedHat/CentOS system tools...${NC}"
        sudo yum install -q -y net-tools procps-ng systemd coreutils findutils grep gawk bc
    elif command -v apk &> /dev/null; then
        echo -e "${CYAN}◢◤ Installing Alpine system tools...${NC}"
        sudo apk add --quiet net-tools procps systemd coreutils findutils grep gawk bc
    fi
}

# Build the application
build_hardend() {
    echo -e "${CYAN}◢◤ Compiling neural interface binary...${NC}"

    # Set build variables
    VERSION="2077.1.0"
    BUILD_TIME=$(date +%s)
    LDFLAGS="-s -w -X main.version=$VERSION -X main.buildTime=$BUILD_TIME"

    # Build for current platform
    progress_bar 3 "Compiling hardend neural interface"

    if go build -ldflags="$LDFLAGS" -o hardend cmd/hardend/main.go; then
        echo -e "${GREEN}◢◤ Neural interface compilation successful${NC}"
    else
        echo -e "${RED}◢◤ FATAL: Compilation failed${NC}"
        exit 1
    fi

    # Make executable
    chmod +x hardend

    # Verify binary
    if ./hardend --version &> /dev/null; then
        echo -e "${GREEN}◢◤ Binary verification passed${NC}"
    else
        echo -e "${RED}◢◤ WARNING: Binary verification failed${NC}"
    fi
}

# Install to system
install_system() {
    echo -e "${CYAN}◢◤ Installing to system neural pathways...${NC}"

    # Create installation directory
    INSTALL_DIR="/opt/hardend"
    sudo mkdir -p "$INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR/configs"
    sudo mkdir -p "$INSTALL_DIR/docs"

    # Copy files
    sudo cp hardend "$INSTALL_DIR/"
    sudo cp -r configs/* "$INSTALL_DIR/configs/" 2>/dev/null || echo "No configs to copy"
    sudo cp -r docs/* "$INSTALL_DIR/docs/" 2>/dev/null || echo "No docs to copy"

    # Create symlink
    sudo ln -sf "$INSTALL_DIR/hardend" "/usr/local/bin/hardend"

    # Set permissions
    sudo chown -R root:root "$INSTALL_DIR"
    sudo chmod +x "$INSTALL_DIR/hardend"

    echo -e "${GREEN}◢◤ System installation complete${NC}"
    echo -e "${GREEN}   Neural interface available at: /usr/local/bin/hardend${NC}"
    echo -e "${GREEN}   Configuration files at: $INSTALL_DIR/configs${NC}"
}

# Create desktop entry (optional)
create_desktop_entry() {
    if command -v desktop-file-install &> /dev/null; then
        echo -e "${CYAN}◢◤ Creating desktop neural link...${NC}"

        cat > hardend.desktop << EOF
[Desktop Entry]
Name=Hardend Security Scanner
Comment=Cyberpunk Linux Security Assessment Tool
Exec=/usr/local/bin/hardend --matrix
Icon=security-high
Terminal=true
Type=Application
Categories=System;Security;
Keywords=security;audit;hardening;cyberpunk;
EOF

        sudo desktop-file-install hardend.desktop
        rm hardend.desktop
        echo -e "${GREEN}◢◤ Desktop neural link created${NC}"
    fi
}

# Run initial test
run_test() {
    echo -e "${CYAN}◢◤ Testing neural interface connectivity...${NC}"

    if hardend --version; then
        echo -e "${GREEN}◢◤ Neural interface test successful${NC}"
        echo ""
        echo -e "${MAGENTA}◢◤ Ready to jack in, samurai!${NC}"
        echo -e "${CYAN}   Run 'hardend --help' for neural interface guide${NC}"
        echo -e "${CYAN}   Run 'hardend --matrix' for full matrix experience${NC}"
    else
        echo -e "${RED}◢◤ Neural interface test failed${NC}"
        exit 1
    fi
}

# Cleanup function
cleanup() {
    echo -e "${CYAN}◢◤ Cleaning up temporary neural pathways...${NC}"
    # Remove any temporary files if needed
}

# Main installation flow
main() {
    print_banner

    echo -e "${CYAN}◢◤ Initializing neural interface installation...${NC}"
    sleep 1

    check_root
    check_requirements
    install_dependencies
    build_hardend

    # Ask for system installation
    echo ""
    read -p "$(echo -e "${YELLOW}Install to system paths? [y/N]: ${NC}")" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_system
        create_desktop_entry
    else
        echo -e "${CYAN}◢◤ Local installation complete${NC}"
        echo -e "${CYAN}   Run './hardend' from current directory${NC}"
    fi

    run_test
    cleanup

    echo ""
    echo -e "${MAGENTA}◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤${NC}"
    echo -e "${MAGENTA}▓▓▓ HARDEND Neural Interface Installation Complete ▓▓▓${NC}"
    echo -e "${MAGENTA}▓▓▓ "Wake the f*ck up, samurai. We have a city to burn." ▓▓▓${NC}"
    echo -e "${MAGENTA}◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤◢◤${NC}"
}

# Trap cleanup on exit
trap cleanup EXIT

# Run main installation
main "$@"
