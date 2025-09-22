#!/bin/bash
# Pat Fortress - Universal Installation Script
# Downloads and installs the latest version of Pat Fortress

set -e

# Configuration
REPO="pat-fortress/pat-fortress"
BINARY_NAME="pat-fortress"
INSTALL_DIR="/usr/local/bin"
VERSION="latest"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "🏰 Pat Fortress Installer"
    echo "========================"
    echo -e "${NC}"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

detect_platform() {
    local os arch

    # Detect OS
    case "$(uname -s)" in
        Linux*)     os="linux" ;;
        Darwin*)    os="darwin" ;;
        FreeBSD*)   os="freebsd" ;;
        OpenBSD*)   os="openbsd" ;;
        CYGWIN*|MINGW*|MSYS*) os="windows" ;;
        *)
            log_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac

    # Detect architecture
    case "$(uname -m)" in
        x86_64|amd64)   arch="amd64" ;;
        arm64|aarch64)  arch="arm64" ;;
        armv7l)         arch="arm" ;;
        *)
            log_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac

    echo "${os}/${arch}"
}

get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/^v//'
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' | sed 's/^v//'
    else
        log_error "Neither curl nor wget is available. Please install one of them."
        exit 1
    fi
}

download_binary() {
    local platform="$1"
    local version="$2"
    local os="${platform%/*}"
    local arch="${platform#*/}"

    local binary_name="${BINARY_NAME}_${version}_${os}_${arch}"
    if [[ "$os" == "windows" ]]; then
        binary_name="${binary_name}.exe"
    fi

    local download_url="https://github.com/${REPO}/releases/download/v${version}/${binary_name}"
    local temp_file="/tmp/${binary_name}"

    log_info "Downloading ${binary_name}..."

    if command -v curl >/dev/null 2>&1; then
        curl -L -o "${temp_file}" "${download_url}"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "${temp_file}" "${download_url}"
    else
        log_error "Neither curl nor wget is available"
        exit 1
    fi

    if [[ ! -f "${temp_file}" ]]; then
        log_error "Failed to download binary"
        exit 1
    fi

    echo "${temp_file}"
}

install_binary() {
    local temp_file="$1"
    local install_path="${INSTALL_DIR}/${BINARY_NAME}"

    # Check if we need sudo
    if [[ ! -w "${INSTALL_DIR}" ]]; then
        log_info "Installing to ${install_path} (requires sudo)..."
        sudo cp "${temp_file}" "${install_path}"
        sudo chmod +x "${install_path}"
    else
        log_info "Installing to ${install_path}..."
        cp "${temp_file}" "${install_path}"
        chmod +x "${install_path}"
    fi

    # Cleanup
    rm -f "${temp_file}"
}

verify_installation() {
    if command -v "${BINARY_NAME}" >/dev/null 2>&1; then
        local installed_version
        installed_version=$("${BINARY_NAME}" --version 2>/dev/null | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' || echo "unknown")
        log_info "✅ Pat Fortress v${installed_version} installed successfully!"
        echo ""
        echo "🚀 Quick Start:"
        echo "   ${BINARY_NAME}                    # Start Pat Fortress"
        echo "   open http://localhost:8025        # Open web interface"
        echo ""
        echo "📧 Configure your app to send emails to localhost:1025"
        echo "📋 Full documentation: https://github.com/${REPO}"
    else
        log_error "Installation verification failed"
        exit 1
    fi
}

check_dependencies() {
    local missing_deps=()

    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        missing_deps+=("curl or wget")
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        echo ""
        echo "Please install the missing dependencies and try again."
        exit 1
    fi
}

main() {
    print_banner

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                VERSION="$2"
                shift 2
                ;;
            --install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            --help)
                echo "Pat Fortress Installer"
                echo ""
                echo "Usage: $0 [options]"
                echo ""
                echo "Options:"
                echo "  --version VERSION    Install specific version (default: latest)"
                echo "  --install-dir DIR    Installation directory (default: /usr/local/bin)"
                echo "  --help              Show this help message"
                echo ""
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    log_info "Checking dependencies..."
    check_dependencies

    log_info "Detecting platform..."
    local platform
    platform=$(detect_platform)
    log_info "Platform: ${platform}"

    if [[ "${VERSION}" == "latest" ]]; then
        log_info "Getting latest version..."
        VERSION=$(get_latest_version)
        if [[ -z "${VERSION}" ]]; then
            log_error "Failed to get latest version"
            exit 1
        fi
    fi
    log_info "Version: ${VERSION}"

    log_info "Downloading binary..."
    local temp_file
    temp_file=$(download_binary "${platform}" "${VERSION}")

    log_info "Installing binary..."
    install_binary "${temp_file}"

    log_info "Verifying installation..."
    verify_installation

    echo ""
    log_info "🎉 Installation complete!"
}

# Run main function
main "$@"