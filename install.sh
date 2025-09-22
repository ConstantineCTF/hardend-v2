#!/bin/bash

# HARDEND Installation Script
# Enterprise Linux Security Assessment Framework

set -e

# Colors for output (minimal, professional)
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Application information
APP_NAME="hardend"
APP_VERSION="2077.1.0"
APP_DESC="Linux Security Hardening Assessment Tool"

# Print header
print_header() {
    echo ""
    echo "HARDEND Installation - Linux Security Assessment Framework"
    echo "Version: $APP_VERSION"
    echo ""
}

# Check system requirements
check_requirements() {
    echo -e "${GREEN}Checking system requirements...${NC}"

    # Check Go installation
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Error: Go compiler not found${NC}"
        echo "Please install Go 1.21+ from https://golang.org/dl/"
        exit 1
    fi

    # Check Go version
    GO_VERSION=$(go version | grep -oP 'go\d+\.\d+' | grep -oP '\d+\.\d+')
    REQUIRED_VERSION="1.21"

    if [[ $(echo "$GO_VERSION >= $REQUIRED_VERSION" | bc -l 2>/dev/null || echo "0") -eq 0 ]]; then
        echo -e "${RED}Error: Go version $GO_VERSION insufficient${NC}"
        echo "Require Go $REQUIRED_VERSION or higher"
        exit 1
    fi

    echo -e "${GREEN}Go $GO_VERSION detected - ready to build${NC}"
}

# Install dependencies
install_dependencies() {
    echo -e "${GREEN}Installing dependencies...${NC}"

    if [[ -f "go.mod" ]]; then
        go mod download
        echo "Dependencies installed successfully"
    else
        echo -e "${RED}Error: go.mod not found${NC}"
        echo "Please run from the project directory"
        exit 1
    fi
}

# Build the application
build_application() {
    echo -e "${GREEN}Building application...${NC}"

    # Build with optimization flags
    LDFLAGS="-s -w -X main.version=$APP_VERSION -X main.buildTime=$(date +%s)"

    if go build -ldflags="$LDFLAGS" -o $APP_NAME cmd/hardend/main.go; then
        echo -e "${GREEN}Build completed successfully${NC}"
    else
        echo -e "${RED}Error: Build failed${NC}"
        exit 1
    fi

    chmod +x $APP_NAME

    # Verify binary
    if ./$APP_NAME --version &> /dev/null; then
        echo -e "${GREEN}Binary verification passed${NC}"
    else
        echo -e "${YELLOW}Warning: Binary verification failed${NC}"
    fi
}

# Install to system (optional)
install_system() {
    echo -e "${GREEN}Installing to system...${NC}"

    INSTALL_DIR="/opt/hardend"
    sudo mkdir -p "$INSTALL_DIR"
    sudo mkdir -p "$INSTALL_DIR/configs"

    # Copy files
    sudo cp $APP_NAME "$INSTALL_DIR/"
    [[ -f "configs/config.yaml" ]] && sudo cp configs/config.yaml "$INSTALL_DIR/configs/"

    # Create symlink
    sudo ln -sf "$INSTALL_DIR/$APP_NAME" "/usr/local/bin/$APP_NAME"

    # Set permissions
    sudo chown -R root:root "$INSTALL_DIR"
    sudo chmod +x "$INSTALL_DIR/$APP_NAME"

    echo -e "${GREEN}System installation complete${NC}"
    echo "Application available at: /usr/local/bin/$APP_NAME"
}

# Test installation
test_installation() {
    echo -e "${GREEN}Testing installation...${NC}"

    if command -v $APP_NAME &> /dev/null; then
        $APP_NAME --version
        echo -e "${GREEN}Installation verified successfully${NC}"
    else
        ./$APP_NAME --version
        echo -e "${GREEN}Local installation verified${NC}"
        echo "Run './$APP_NAME' from current directory"
    fi
}

# Main installation process
main() {
    print_header

    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        echo -e "${YELLOW}Warning: Running as root${NC}"
        echo "Some security checks may be bypassed when run as root"
        echo ""
    fi

    check_requirements
    install_dependencies
    build_application

    # Ask for system installation
    echo ""
    read -p "Install to system paths? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_system
    fi

    test_installation

    echo ""
    echo -e "${GREEN}HARDEND installation complete!${NC}"
    echo "Ready to perform Linux security assessments."
    echo ""
    echo "Usage:"
    echo "  $APP_NAME                    # Full security assessment"
    echo "  $APP_NAME --help             # Show help information"
    echo "  $APP_NAME -format json       # Generate JSON report"
    echo ""
}

# Run installation
main "$@"
