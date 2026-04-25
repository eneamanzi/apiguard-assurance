#!/bin/bash

set -euo pipefail
shopt -s nullglob

show_help() {
    cat << EOF
Usage: ./build_zip.sh [OPTIONS]

Builds an optimized zip archive ("apiguard-assurance.zip") for LLM consumption.
It automatically excludes Git history, caches, heavy payload data, 
integration tests, and non-target domains to save context tokens.

Options:
  -d <numbers>  Specify the Domain number(s) to include, comma-separated (e.g., -d 6 or -d 1,4,6).
                All other domain test folders and config files will be excluded.
  -h            Show this help message and exit.

Examples:
  ./build_zip.sh -d 6       # Keeps ONLY domain 6
  ./build_zip.sh -d 1,4,6   # Keeps domains 1, 4, and 6
  ./build_zip.sh            # Zips the entire project
EOF
}

if ! command -v zip &> /dev/null; then
    echo "[ERROR] The 'zip' command is not installed on this system."
    exit 1
fi

if [ ! -f "pyproject.toml" ]; then
    echo "[ERROR] You must run this script from the project root (where pyproject.toml is located)."
    exit 1
fi

OUTPUT="apiguard-assurance.zip"

TARGET_DOMAIN_STR=""
while getopts "hd:" opt; do
  case $opt in
    h) show_help; exit 0 ;;
    d) TARGET_DOMAIN_STR="$OPTARG" ;;
    \?) show_help >&2; exit 1 ;;
  esac
done

rm -f "$OUTPUT"

EXCLUDES=(
    "*.git/*"
    "*__pycache__*"
    "*.pyc"
    "*.ruff_cache*"
    "*.pytest_cache*"
    "*.mypy_cache*"
    "*.vscode*"
    "*outputs/*"
    "*specs/*"
    "*.zip"
    ".env"
    "tests_integration/*"
    "src/report/templates/*"
)

if [ -n "$TARGET_DOMAIN_STR" ]; then
    echo "[INFO] Building LLM context package for Domain(s): $TARGET_DOMAIN_STR..."
    
    # Converte la stringa separata da virgole in un array
    IFS=',' read -r -a TARGET_DOMAINS <<< "$TARGET_DOMAIN_STR"
    
    for DIR in src/tests/domain_*; do
        if [ -d "$DIR" ]; then
            DOMAIN_NUM=$(echo "$DIR" | grep -oE '[0-9]+$')
            KEEP=false
            for TD in "${TARGET_DOMAINS[@]}"; do
                # Rimuove eventuali spazi extra
                TD=$(echo "$TD" | xargs)
                if [ "$DOMAIN_NUM" == "$TD" ]; then
                    KEEP=true
                    break
                fi
            done
            if [ "$KEEP" = false ]; then
                EXCLUDES+=("$DIR/*")
            fi
        fi
    done

    for FILE in src/config/schema/domain_*.py; do
        if [ -f "$FILE" ]; then
            DOMAIN_NUM=$(echo "$FILE" | grep -oE '[0-9]+' | tail -n 1)
            KEEP=false
            for TD in "${TARGET_DOMAINS[@]}"; do
                TD=$(echo "$TD" | xargs)
                if [ "$DOMAIN_NUM" == "$TD" ]; then
                    KEEP=true
                    break
                fi
            done
            if [ "$KEEP" = false ]; then
                EXCLUDES+=("$FILE")
            fi
        fi
    done
else
    echo "[WARNING] No specific domain requested (-d). Zipping all source code."
fi

echo "[INFO] Aggiornamento API Reference tramite Hatch (ambiente dev)..."
hatch run dev:docs

zip -r "$OUTPUT" . -x "${EXCLUDES[@]}" > /dev/null

SIZE=$(du -h "$OUTPUT" | cut -f1)
echo "[SUCCESS] Created '$OUTPUT' (Size: $SIZE)"