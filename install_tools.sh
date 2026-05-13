#!/bin/bash
# Abort on first error.
set -e

# Terminal colours.
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No colour.

echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}   APIGuard - Tool Installation Script ${NC}"
echo -e "${BLUE}=======================================${NC}"

# 1. Create the local tools sandbox directory.
TOOLS_DIR="./tools"
mkdir -p "$TOOLS_DIR"
echo -e "${GREEN}[+] Directory $TOOLS_DIR ready.${NC}"

# ==========================================
# TOOL 1: testssl.sh
# ==========================================
TESTSSL_VERSION="3.2.3"
TESTSSL_TARGET_DIR="$TOOLS_DIR/testssl"

# Skip download if already installed to avoid redundant network calls.
if [ ! -f "$TESTSSL_TARGET_DIR/testssl.sh" ]; then
    echo -e "${GREEN}[+] Downloading testssl.sh v$TESTSSL_VERSION ...${NC}"

    # Download tarball (works on both macOS and Linux).
    curl -sL "https://github.com/drwetter/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz" -o testssl.tar.gz

    # Extract archive.
    tar -xzf testssl.tar.gz

    # Rename directory and remove archive.
    mv "testssl.sh-${TESTSSL_VERSION}" "$TESTSSL_TARGET_DIR"
    rm testssl.tar.gz

    # Make binary executable.
    chmod +x "$TESTSSL_TARGET_DIR/testssl.sh"

    echo -e "${GREEN}[✓] testssl.sh v$TESTSSL_VERSION installed at $TESTSSL_TARGET_DIR/testssl.sh${NC}"
else
    echo -e "${GREEN}[✓] testssl.sh already installed.${NC}"
fi

# ==========================================
# TOOL 2: nuclei
# ==========================================
# Go binary: OS- and architecture-specific.
# The pinned version ensures reproducible results: field names and JSON
# schema can change between releases.
# To upgrade: update NUCLEI_VERSION, delete ./tools/nuclei/, and verify
# that NucleiConnector._evaluate() is still compatible with the new JSON
# schema (see Step B.0 in docs/ADDING_EXTERNAL_TESTS.md).
NUCLEI_VERSION="3.8.0"
NUCLEI_TARGET_DIR="$TOOLS_DIR/nuclei"

if [ ! -f "$NUCLEI_TARGET_DIR/nuclei" ]; then
    echo -e "${GREEN}[+] Downloading nuclei v$NUCLEI_VERSION ...${NC}"

    # Detect OS.
    OS_RAW="$(uname -s)"
    case "$OS_RAW" in
        Linux)  OS_STR="linux" ;;
        Darwin) OS_STR="macOS" ;;
        *)
            echo "ERROR: Unsupported OS: $OS_RAW"
            exit 1
            ;;
    esac

    # Detect architecture.
    ARCH_RAW="$(uname -m)"
    case "$ARCH_RAW" in
        x86_64)          ARCH_STR="amd64" ;;
        arm64|aarch64)   ARCH_STR="arm64" ;;
        *)
            echo "ERROR: Unsupported architecture: $ARCH_RAW"
            exit 1
            ;;
    esac

    NUCLEI_ZIP="nuclei_${NUCLEI_VERSION}_${OS_STR}_${ARCH_STR}.zip"
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/${NUCLEI_ZIP}"

    echo -e "${GREEN}    Downloading: ${NUCLEI_ZIP}${NC}"
    mkdir -p "$NUCLEI_TARGET_DIR"
    curl -sL "$NUCLEI_URL" -o nuclei.zip
    unzip -q nuclei.zip -d "$NUCLEI_TARGET_DIR"
    rm nuclei.zip
    chmod +x "$NUCLEI_TARGET_DIR/nuclei"

    echo -e "${GREEN}[✓] nuclei v$NUCLEI_VERSION installed at $NUCLEI_TARGET_DIR/nuclei${NC}"
    echo -e "${GREEN}    OS: $OS_STR | Arch: $ARCH_STR${NC}"
else
    echo -e "${GREEN}[✓] nuclei already installed.${NC}"
fi

# ==========================================
# TOOL 2b: nuclei-templates (pinned)
# ==========================================
# Templates are a separate dependency from the nuclei binary.
# The version is pinned to guarantee reproducible results: the same
# template_id produces the same finding regardless of when the scan runs.
# To upgrade: update NUCLEI_TEMPLATES_VERSION, delete ./tools/nuclei-templates/,
# and verify compatibility with NUCLEI_VERSION and _evaluate() in the connector.
# Version relationship: nuclei-templates v10.4.3 was released alongside
# nuclei v3.8.0 and has been verified compatible with NucleiConnector's parser.
NUCLEI_TEMPLATES_VERSION="10.4.3"
NUCLEI_TEMPLATES_DIR="$TOOLS_DIR/nuclei-templates"

if [ ! -d "$NUCLEI_TEMPLATES_DIR/.git" ] && [ ! -f "$NUCLEI_TEMPLATES_DIR/.templates-checksum" ]; then
    echo -e "${GREEN}[+] Downloading nuclei-templates v$NUCLEI_TEMPLATES_VERSION ...${NC}"

    TEMPLATES_URL="https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz"

    curl -sL "$TEMPLATES_URL" -o nuclei-templates.tar.gz
    tar -xzf nuclei-templates.tar.gz
    mv "nuclei-templates-${NUCLEI_TEMPLATES_VERSION}" "$NUCLEI_TEMPLATES_DIR"
    rm nuclei-templates.tar.gz

    # Marker file: records the installed version for quick inspection
    # without reading .git or invoking nuclei -tv.
    echo "$NUCLEI_TEMPLATES_VERSION" > "$NUCLEI_TEMPLATES_DIR/.templates-checksum"

    echo -e "${GREEN}[✓] nuclei-templates v$NUCLEI_TEMPLATES_VERSION installed at $NUCLEI_TEMPLATES_DIR${NC}"
else
    INSTALLED=$(cat "$NUCLEI_TEMPLATES_DIR/.templates-checksum" 2>/dev/null || echo "unknown")
    echo -e "${GREEN}[✓] nuclei-templates already installed (v$INSTALLED).${NC}"
fi

echo -e "${BLUE}=======================================${NC}"
echo -e "${GREEN}[✓] All tools are ready.${NC}"
