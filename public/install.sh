#!/bin/bash
set -euo pipefail

BOLD="\033[1m"
DIM="\033[2m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

MIN_NODE_VERSION=18

info()  { echo -e "${BOLD}${GREEN}>>>${RESET} $1"; }
warn()  { echo -e "${BOLD}${YELLOW}>>>${RESET} $1"; }
error() { echo -e "${BOLD}${RED}>>>${RESET} $1"; exit 1; }

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"
  case "$OS" in
    Darwin) PLATFORM="macOS" ;;
    Linux)  PLATFORM="Linux" ;;
    *)      error "Unsupported OS: $OS" ;;
  esac
  case "$ARCH" in
    x86_64|amd64)  ARCH_LABEL="x64" ;;
    arm64|aarch64) ARCH_LABEL="arm64" ;;
    *)             error "Unsupported architecture: $ARCH" ;;
  esac
  info "Detected ${PLATFORM} (${ARCH_LABEL})"
}

check_node() {
  if ! command -v node &>/dev/null; then
    warn "Node.js is not installed."
    echo "  Install Node.js >= ${MIN_NODE_VERSION}:"
    echo "    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash"
    echo "    nvm install --lts"
    error "Please install Node.js and re-run this script."
  fi
  NODE_VERSION=$(node -v | sed 's/^v//' | cut -d. -f1)
  if [ "$NODE_VERSION" -lt "$MIN_NODE_VERSION" ]; then
    error "Node.js v${NODE_VERSION} found, but >= v${MIN_NODE_VERSION} is required."
  fi
  info "Node.js $(node -v) detected"
}

INSTALL_DIR="${HOME}/.gate/app"

install_gate() {
  if command -v git &>/dev/null; then
    info "Installing Gate from GitHub..."
    if [ -d "${INSTALL_DIR}/.git" ]; then
      info "Existing installation found, updating..."
      cd "${INSTALL_DIR}"
      git pull --ff-only || error "git pull failed. Delete ~/.gate/app and re-run."
    else
      rm -rf "${INSTALL_DIR}"
      git clone --depth 1 https://github.com/penumbraforge/gate.git "${INSTALL_DIR}" || error "git clone failed."
      cd "${INSTALL_DIR}"
    fi
  else
    info "git not found, installing via npm tarball..."
    npm install -g https://github.com/penumbraforge/gate/tarball/main || error "npm install failed."
    return 0
  fi

  info "Installing dependencies..."
  npm install --production=false || error "npm install failed."

  info "Building..."
  npm run build || error "Build failed."

  # Symlink gate binary
  GATE_BIN="${INSTALL_DIR}/bin/gate.js"
  NPM_BIN_DIR="$(npm bin -g 2>/dev/null || npm prefix -g)/bin"
  mkdir -p "${NPM_BIN_DIR}" 2>/dev/null || true

  if [ -w "${NPM_BIN_DIR}" ]; then
    ln -sf "${GATE_BIN}" "${NPM_BIN_DIR}/gate" 2>/dev/null && info "Linked gate to ${NPM_BIN_DIR}/gate"
  fi

  # Also link to ~/.gate/bin for PATH fallback
  mkdir -p "${HOME}/.gate/bin"
  printf '#!/bin/sh\nexec node "${HOME}/.gate/app/bin/gate.js" "$@"\n' > "${HOME}/.gate/bin/gate"
  chmod +x "${HOME}/.gate/bin/gate"
  info "Installed to ~/.gate/bin/gate"
}

add_to_path() {
  GATE_BIN_DIR="${HOME}/.gate/bin"
  case ":${PATH}:" in
    *":${GATE_BIN_DIR}:"*) return ;;
  esac

  for RC_FILE in "${HOME}/.zshrc" "${HOME}/.bashrc" "${HOME}/.profile"; do
    if [ -f "${RC_FILE}" ]; then
      if ! grep -q '.gate/bin' "${RC_FILE}" 2>/dev/null; then
        echo "" >> "${RC_FILE}"
        echo '# Penumbra Gate' >> "${RC_FILE}"
        echo 'export PATH="${HOME}/.gate/bin:${PATH}"' >> "${RC_FILE}"
        info "Added ~/.gate/bin to PATH in $(basename ${RC_FILE})"
      fi
    fi
  done
  export PATH="${GATE_BIN_DIR}:${PATH}"
}

main() {
  echo ""
  echo -e "${BOLD}Penumbra Gate Installer${RESET}"
  echo "─────────────────────────────────"
  echo ""
  detect_platform
  check_node
  if ! command -v npm &>/dev/null; then error "npm not found."; fi
  info "npm $(npm -v) detected"
  install_gate
  add_to_path

  # Run setup if possible
  if command -v gate &>/dev/null; then
    info "Running first-time setup..."
    gate setup --skip-db
  elif [ -f "${HOME}/.gate/app/bin/gate.js" ]; then
    info "Running first-time setup..."
    node "${HOME}/.gate/app/bin/gate.js" setup --skip-db
  fi

  echo ""
  echo -e "${GREEN}${BOLD}Gate installed successfully!${RESET}"
  echo ""
  echo "  gate scan           Scan staged files for secrets"
  echo "  gate install        Install pre-commit hook"
  echo "  gate serve          Start the dashboard on :3000"
  echo ""
  echo "  If 'gate' is not found, restart your terminal or run:"
  echo "    export PATH=\"\$HOME/.gate/bin:\$PATH\""
  echo ""
}

main
