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

# ==========================================
# TOOL 2: nuclei
# ==========================================
# Binario Go: dipende da OS e architettura.
# La versione pinnata garantisce riproducibilità dei risultati
# (field names e formato JSON possono cambiare tra release).
# Per aggiornare: cambia NUCLEI_VERSION e cancella ./tools/nuclei/
# Prima di aggiornare: verifica che NucleiConnector._evaluate() sia
# ancora compatibile con il nuovo formato JSON (Step B.0 nel manuale).
NUCLEI_VERSION="3.8.0"
NUCLEI_TARGET_DIR="$TOOLS_DIR/nuclei"

if [ ! -f "$NUCLEI_TARGET_DIR/nuclei" ]; then
    echo -e "${GREEN}[+] Download nuclei v$NUCLEI_VERSION in corso...${NC}"

    # Rileva OS
    OS_RAW="$(uname -s)"
    case "$OS_RAW" in
        Linux)  OS_STR="linux" ;;
        Darwin) OS_STR="macOS" ;;
        *)
            echo "ERRORE: OS non supportato: $OS_RAW"
            exit 1
            ;;
    esac

    # Rileva architettura
    ARCH_RAW="$(uname -m)"
    case "$ARCH_RAW" in
        x86_64)          ARCH_STR="amd64" ;;
        arm64|aarch64)   ARCH_STR="arm64" ;;
        *)
            echo "ERRORE: Architettura non supportata: $ARCH_RAW"
            exit 1
            ;;
    esac

    NUCLEI_ZIP="nuclei_${NUCLEI_VERSION}_${OS_STR}_${ARCH_STR}.zip"
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/${NUCLEI_ZIP}"

    echo -e "${GREEN}    Scaricando: ${NUCLEI_ZIP}${NC}"
    mkdir -p "$NUCLEI_TARGET_DIR"
    curl -sL "$NUCLEI_URL" -o nuclei.zip
    unzip -q nuclei.zip -d "$NUCLEI_TARGET_DIR"
    rm nuclei.zip
    chmod +x "$NUCLEI_TARGET_DIR/nuclei"

    echo -e "${GREEN}[✓] nuclei v$NUCLEI_VERSION installato in $NUCLEI_TARGET_DIR/nuclei${NC}"
    echo -e "${GREEN}    OS: $OS_STR | Arch: $ARCH_STR${NC}"
else
    echo -e "${GREEN}[✓] nuclei è già installato.${NC}"
fi

# ==========================================
# TOOL 2b: nuclei-templates (pinned)
# ==========================================
# I template sono una dipendenza separata dal binario.
# La versione è pinnata per garantire riproducibilità:
# lo stesso template_id produce lo stesso finding indipendentemente
# da quando viene eseguita la scansione.
# Per aggiornare: cambia NUCLEI_TEMPLATES_VERSION, cancella ./tools/nuclei-templates/
# e verifica la compatibilità con NUCLEI_VERSION e con _evaluate() nel connector.
# Relazione versioni: nuclei-templates v10.4.3 è la versione rilasciata contestualmente
# a nuclei v3.8.0 e verificata compatibile con il parser in NucleiConnector.
NUCLEI_TEMPLATES_VERSION="10.4.3"
NUCLEI_TEMPLATES_DIR="$TOOLS_DIR/nuclei-templates"

if [ ! -d "$NUCLEI_TEMPLATES_DIR/.git" ] && [ ! -f "$NUCLEI_TEMPLATES_DIR/.templates-checksum" ]; then
    echo -e "${GREEN}[+] Download nuclei-templates v$NUCLEI_TEMPLATES_VERSION in corso...${NC}"

    TEMPLATES_URL="https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${NUCLEI_TEMPLATES_VERSION}.tar.gz"

    curl -sL "$TEMPLATES_URL" -o nuclei-templates.tar.gz
    tar -xzf nuclei-templates.tar.gz
    mv "nuclei-templates-${NUCLEI_TEMPLATES_VERSION}" "$NUCLEI_TEMPLATES_DIR"
    rm nuclei-templates.tar.gz

    # Marker file: registra la versione installata per ispezione rapida
    # senza dover leggere .git o invocare nuclei -tv.
    echo "$NUCLEI_TEMPLATES_VERSION" > "$NUCLEI_TEMPLATES_DIR/.templates-checksum"

    echo -e "${GREEN}[✓] nuclei-templates v$NUCLEI_TEMPLATES_VERSION installati in $NUCLEI_TEMPLATES_DIR${NC}"
else
    INSTALLED=$(cat "$NUCLEI_TEMPLATES_DIR/.templates-checksum" 2>/dev/null || echo "unknown")
    echo -e "${GREEN}[✓] nuclei-templates sono già installati (v$INSTALLED).${NC}"
fi

echo -e "${BLUE}=======================================${NC}"
echo -e "${GREEN}[✓] Tutti i tool sono pronti all'uso!${NC}"