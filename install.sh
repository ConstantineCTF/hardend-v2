#!/bin/bash

# HARDEND Installation Script
# Professional Linux Security Assessment Framework

set -e

# Colors for output (minimal, professional)
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --- Configuration ---
APP_NAME="hardend"
APP_VERSION="2.0.0" # Updated Version
APP_DESC="Linux Security Hardening Assessment Tool"
GO_REQUIRED_VERSION="1.25"
INSTALL_BIN_DIR="/usr/local/bin"
INSTALL_DATA_DIR="/usr/local/share/hardend"
# --- End Configuration ---

# Print header
print_header() {
    echo ""
    echo "HARDEND Installation - $APP_DESC"
    echo "Version: $APP_VERSION"
    echo ""
}

# Check system requirements
check_requirements() {
    echo -e "${GREEN}Checking system requirements...${NC}"

    # Check Go installation
    if ! command -v go &> /dev/null; then
        echo -e "${RED}Error: Go compiler not found.${NC}"
        echo "Please install Go $GO_REQUIRED_VERSION+ from https://golang.org/dl/"
        return 1
    fi

    # Check Go version
    GO_VERSION=$(go version | grep -oE 'go[0-9]+\.[0-9]+(\.[0-9]+)?' | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?')
    if ! $(go version | awk -v req="$GO_REQUIRED_VERSION" '{ split($3, v, "go"); split(v[2], ver, "."); split(req, r, "."); if (ver[1] < r[1] || (ver[1] == r[1] && ver[2] < r[2])) exit 1; exit 0 }'); then
        echo -e "${RED}Error: Go version $GO_VERSION is insufficient.${NC}"
        echo "Requires Go $GO_REQUIRED_VERSION or higher."
        return 1
    fi

    echo -e "${GREEN}Go $GO_VERSION detected.${NC}"
    return 0
}

# Install dependencies via Go modules
install_dependencies() {
    echo -e "${GREEN}Downloading dependencies...${NC}"
    if [[ -f "go.mod" ]]; then
        if go mod download; then
             echo -e "${GREEN}Dependencies downloaded successfully.${NC}"
        else
            echo -e "${RED}Error: Failed to download Go modules.${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Error: go.mod not found. Please run from the project root directory.${NC}"
        exit 1
    fi
}

# Build the application
build_application() {
    echo -e "${GREEN}Building application binary...${NC}"

    # Build flags: Strip symbols, set version variable (ensure 'appVersion' exists in main package)
    # The variable path '-X main.appVersion=...' must match the actual variable in your main.go
    # If you don't have such a variable, remove the -X flag or add it to main.go: var appVersion string
    BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    LDFLAGS="-s -w -X main.appVersion=$APP_VERSION -X main.buildTime=$BUILD_TIME"

    if go build -ldflags="$LDFLAGS" -o $APP_NAME cmd/hardend/main.go; then
        echo -e "${GREEN}Build successful: '$APP_NAME' binary created.${NC}"
    else
        echo -e "${RED}Error: Build failed.${NC}"
        exit 1
    fi
    chmod +x $APP_NAME
}

# Install to system (optional)
install_system() {
    echo -e "${GREEN}Attempting system-wide installation...${NC}"
    if [[ $EUID -ne 0 ]]; then
       echo -e "${YELLOW}System-wide installation requires root privileges. Please run with sudo or as root.${NC}"
       return 1
    fi

    echo "Creating directories..."
    mkdir -p "$INSTALL_DATA_DIR/configs"

    echo "Copying files..."
    cp "$APP_NAME" "$INSTALL_DATA_DIR/"
    if [[ -f "configs/config.yaml" ]]; then
        cp configs/config.yaml "$INSTALL_DATA_DIR/configs/"
        chown root:root "$INSTALL_DATA_DIR/configs/config.yaml"
        chmod 644 "$INSTALL_DATA_DIR/configs/config.yaml"
    else
        echo -e "${YELLOW}Warning: Default config.yaml not found in ./configs/.${NC}"
    fi

    echo "Creating symlink..."
    ln -sf "$INSTALL_DATA_DIR/$APP_NAME" "$INSTALL_BIN_DIR/$APP_NAME"

    echo "Setting permissions..."
    chown -R root:root "$INSTALL_DATA_DIR"
    chmod +x "$INSTALL_DATA_DIR/$APP_NAME"

    echo -e "${GREEN}System installation complete.${NC}"
    echo "Application available at: $INSTALL_BIN_DIR/$APP_NAME"
    echo "Default configuration directory: $INSTALL_DATA_DIR/configs/"
}

# Test installation
test_installation() {
    echo -e "${GREEN}Verifying installation...${NC}"
    APP_PATH=$(command -v $APP_NAME) # Find where the command is located

    # Check if the command exists in the PATH and is executable
    if [[ -n "$APP_PATH" ]] && [[ -x "$APP_PATH" ]]; then
        echo -n "System-wide ($APP_PATH): "
        if $APP_NAME --version &> /dev/null; then
            echo -e "${GREEN}OK${NC}"
            $APP_NAME --version
        else
            echo -e "${RED}Failed. Could not execute $APP_NAME from PATH.${NC}"
            return 1
        fi
    # Fallback check for local build if not found in PATH
    elif [[ -f "./$APP_NAME" ]] && [[ -x "./$APP_NAME" ]]; then
        echo -n "Local build (./$APP_NAME): "
        if ./$APP_NAME --version &> /dev/null; then
            echo -e "${GREEN}OK${NC}"
            ./$APP_NAME --version
            echo "Run './$APP_NAME' from this directory."
        else
            echo -e "${RED}Failed. Could not execute ./$APP_NAME.${NC}"
            return 1
        fi
    else
        echo -e "${RED}Error: $APP_NAME binary not found in system PATH or current directory.${NC}"
        return 1
    fi
    return 0
}

# Main installation process
main() {
    print_header

    check_requirements || exit 1
    install_dependencies
    build_application

    # Optional: Run tests after build
    # echo -e "${GREEN}Running tests...${NC}"
    # if ! go test ./tests/...; then
    #     echo -e "${RED}Error: Tests failed. Aborting installation.${NC}"
    #     exit 1
    # fi
    # echo -e "${GREEN}Tests passed.${NC}"

    echo ""
    read -p "Install $APP_NAME system-wide to $INSTALL_BIN_DIR? [y/N]: " -n 1 -r REPLY
    echo # Move to new line
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_system || echo -e "${YELLOW}System-wide installation skipped or failed.${NC}"
    else
        echo "Skipping system-wide installation."
    fi

    echo ""
    if test_installation; then
        echo -e "${GREEN}HARDEND installation complete!${NC}"
        echo "Run '$APP_NAME --help' for usage instructions."
    else
        echo -e "${RED}Installation verification failed.${NC}"
        exit 1
    fi
    echo ""
}

# Run installation
main "$@"
