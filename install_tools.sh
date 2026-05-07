#!/bin/bash
# Ferma lo script in caso di errori
set -e

# Colori per un output leggibile da terminale
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # Nessun colore

echo -e "${BLUE}=======================================${NC}"
echo -e "${BLUE}   APIGuard - Tool Installation Script ${NC}"
echo -e "${BLUE}=======================================${NC}"

# 1. Creazione della directory "sandbox"
TOOLS_DIR="./tools"
mkdir -p "$TOOLS_DIR"
echo -e "${GREEN}[+] Cartella $TOOLS_DIR pronta.${NC}"

# ==========================================
# TOOL 1: testssl.sh
# ==========================================
TESTSSL_VERSION="3.2.3"
TESTSSL_TARGET_DIR="$TOOLS_DIR/testssl"

# Controlla se è già installato per evitare download ripetuti
if [ ! -f "$TESTSSL_TARGET_DIR/testssl.sh" ]; then
    echo -e "${GREEN}[+] Download testssl.sh v$TESTSSL_VERSION in corso...${NC}"
    
    # Scarica il tarball (funziona sia su Mac che su Linux)
    curl -sL "https://github.com/drwetter/testssl.sh/archive/refs/tags/v${TESTSSL_VERSION}.tar.gz" -o testssl.tar.gz
    
    # Estrae l'archivio
    tar -xzf testssl.tar.gz
    
    # Rinomina la cartella per pulizia e rimuove l'archivio
    mv "testssl.sh-${TESTSSL_VERSION}" "$TESTSSL_TARGET_DIR"
    rm testssl.tar.gz
    
    # Rende il binario eseguibile
    chmod +x "$TESTSSL_TARGET_DIR/testssl.sh"
    
    echo -e "${GREEN}[✓] testssl.sh v$TESTSSL_VERSION installato con successo in $TESTSSL_TARGET_DIR/testssl.sh${NC}"
else
    echo -e "${GREEN}[✓] testssl.sh è già installato.${NC}"
fi

echo -e "${BLUE}=======================================${NC}"
echo -e "${GREEN}[✓] Tutti i tool sono pronti all'uso!${NC}"