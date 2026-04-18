#!/usr/bin/env bash
# ============================================================================
# K.O.D.A. — Kinetic Operative Defense Agent
# ============================================================================
# Open-source AI security agent harness — by Vektra Industries
#
# Usage:
#   curl -fsSL https://koda.vektraindustries.com/install | bash
#
# Options:
#   curl -fsSL ... | bash -s -- --branch dev
#   curl -fsSL ... | bash -s -- --dir ~/my-koda
#   curl -fsSL ... | bash -s -- --no-wizard
# ============================================================================

set -euo pipefail

# ── Colors ─────────────────────────────────────────────────────────
GOLD='\033[38;5;178m'
GREEN='\033[32m'
RED='\033[31m'
CYAN='\033[36m'
YELLOW='\033[33m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Configuration ──────────────────────────────────────────────────
REPO_URL_SSH="git@github.com:PabloTheThinker/K.O.D.A..git"
REPO_URL_HTTPS="https://github.com/PabloTheThinker/K.O.D.A..git"
KODA_HOME="${KODA_HOME:-$HOME/koda}"
INSTALL_DIR="${KODA_INSTALL_DIR:-$KODA_HOME}"
MIN_PYTHON="3.11"
BRANCH="main"
RUN_WIZARD=1

while [[ $# -gt 0 ]]; do
    case $1 in
        --branch)       BRANCH="$2"; shift 2 ;;
        --dir)          INSTALL_DIR="$2"; KODA_HOME="$2"; shift 2 ;;
        --no-wizard)    RUN_WIZARD=0; shift ;;
        -h|--help)
            echo "K.O.D.A. Installer"
            echo ""
            echo "Options:"
            echo "  --branch NAME   Git branch (default: main)"
            echo "  --dir PATH      Install directory (default: ~/koda)"
            echo "  --no-wizard     Skip the setup wizard"
            echo "  -h, --help      Show this help"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Helpers ────────────────────────────────────────────────────────
info()  { printf "${CYAN}→${RESET} %s\n" "$1"; }
ok()    { printf "${GREEN}✓${RESET} %s\n" "$1"; }
warn()  { printf "${YELLOW}⚠${RESET} %s\n" "$1"; }
fail()  { printf "${RED}✗${RESET} %s\n" "$1"; exit 1; }

# ── Platform detection ─────────────────────────────────────────────
detect_platform() {
    case "$(uname -s)" in
        Linux*)
            OS="linux"
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                DISTRO="$ID"
            else
                DISTRO="unknown"
            fi
            ;;
        Darwin*) OS="macos"; DISTRO="macos" ;;
        CYGWIN*|MINGW*|MSYS*)
            fail "Windows detected. Use WSL: wsl --install, then re-run this script inside WSL."
            ;;
        *) fail "Unsupported OS: $(uname -s)." ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64)  ARCH="x64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *)             ARCH="$(uname -m)" ;;
    esac

    if [ "$OS" = "macos" ] && [ "$ARCH" = "x64" ]; then
        if [ "$(sysctl -n sysctl.proc_translated 2>/dev/null)" = "1" ]; then
            ARCH="arm64"
        fi
    fi

    ok "Platform: $OS-$ARCH ($DISTRO)"
}

# ── Dependency: uv ─────────────────────────────────────────────────
ensure_uv() {
    for loc in "$(command -v uv 2>/dev/null || true)" "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv"; do
        if [ -n "$loc" ] && [ -x "$loc" ]; then
            UV_CMD="$loc"
            ok "uv found"
            return 0
        fi
    done

    info "Installing uv..."
    if curl -LsSf https://astral.sh/uv/install.sh | sh 2>/dev/null; then
        for loc in "$HOME/.local/bin/uv" "$HOME/.cargo/bin/uv" "$(command -v uv 2>/dev/null || true)"; do
            if [ -n "$loc" ] && [ -x "$loc" ]; then
                UV_CMD="$loc"
                ok "uv installed"
                return 0
            fi
        done
        fail "uv installed but not on PATH. Add ~/.local/bin to PATH and re-run."
    else
        fail "Failed to install uv. See https://docs.astral.sh/uv/"
    fi
}

# ── Dependency: Python ─────────────────────────────────────────────
ensure_python() {
    if $UV_CMD python find "$MIN_PYTHON" &>/dev/null; then
        PYTHON_PATH=$($UV_CMD python find "$MIN_PYTHON")
        ok "Python $($PYTHON_PATH --version 2>&1 | awk '{print $2}')"
        return 0
    fi

    info "Installing Python $MIN_PYTHON via uv..."
    if $UV_CMD python install "$MIN_PYTHON"; then
        PYTHON_PATH=$($UV_CMD python find "$MIN_PYTHON")
        ok "Python installed"
    else
        fail "Failed to install Python. Install Python $MIN_PYTHON+ manually, then re-run."
    fi
}

# ── Dependency: Git ────────────────────────────────────────────────
ensure_git() {
    if command -v git &>/dev/null; then
        ok "Git $(git --version | awk '{print $3}')"
        return 0
    fi

    printf "${RED}✗${RESET} Git not found. Install it first:\n"
    case "$OS" in
        linux)
            case "$DISTRO" in
                ubuntu|debian) echo "  sudo apt install git" ;;
                fedora)        echo "  sudo dnf install git" ;;
                arch)          echo "  sudo pacman -S git" ;;
                *)             echo "  Install git with your package manager" ;;
            esac
            ;;
        macos) echo "  xcode-select --install" ;;
    esac
    exit 1
}

# ── Clone / update source ──────────────────────────────────────────
fetch_source() {
    SOURCE_DIR="$INSTALL_DIR/.source"

    if [ -d "$SOURCE_DIR/.git" ]; then
        info "Updating existing installation..."
        cd "$SOURCE_DIR"
        git fetch origin 2>/dev/null
        git checkout "$BRANCH" 2>/dev/null
        git pull --ff-only origin "$BRANCH" 2>/dev/null || git reset --hard "origin/$BRANCH"
        ok "Source updated"
    else
        info "Downloading K.O.D.A...."
        mkdir -p "$INSTALL_DIR"
        if GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=5" \
           git clone --depth 1 --branch "$BRANCH" "$REPO_URL_SSH" "$SOURCE_DIR" 2>/dev/null; then
            ok "Downloaded via SSH"
        else
            rm -rf "$SOURCE_DIR" 2>/dev/null
            if git clone --depth 1 --branch "$BRANCH" "$REPO_URL_HTTPS" "$SOURCE_DIR"; then
                ok "Downloaded"
            else
                fail "Failed to download K.O.D.A."
            fi
        fi
    fi
}

# ── Create venv + install ──────────────────────────────────────────
install_koda() {
    VENV_DIR="$INSTALL_DIR/.venv"

    if [ ! -d "$VENV_DIR" ]; then
        info "Creating environment..."
        $UV_CMD venv "$VENV_DIR" --python "$MIN_PYTHON" --quiet
    fi

    info "Installing K.O.D.A...."
    export VIRTUAL_ENV="$VENV_DIR"

    # Stream real errors — debugging an unhappy install was impossible
    # when stderr went to /dev/null.
    if ! $UV_CMD pip install "$SOURCE_DIR"; then
        warn "First install attempt failed \u2014 retrying against a fresh venv..."
        rm -rf "$VENV_DIR"
        $UV_CMD venv "$VENV_DIR" --python "$MIN_PYTHON" --quiet
        export VIRTUAL_ENV="$VENV_DIR"
        if ! $UV_CMD pip install "$SOURCE_DIR"; then
            fail "Installation failed. See errors above."
        fi
    fi
    ok "Installed"
}

# ── Shell integration ──────────────────────────────────────────────
setup_shell() {
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"

    # Launcher wrapper — unsets PYTHONHASHSEED to avoid inherited bad values
    cat > "$BIN_DIR/koda" << LAUNCHER
#!/usr/bin/env bash
# K.O.D.A. launcher — generated by installer
unset PYTHONHASHSEED
exec "$VENV_DIR/bin/koda" "\$@"
LAUNCHER
    chmod +x "$BIN_DIR/koda"

    if echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
        ok "koda on PATH"
    else
        SHELL_RC=""
        LOGIN_SHELL="$(basename "${SHELL:-/bin/bash}")"
        case "$LOGIN_SHELL" in
            zsh) SHELL_RC="$HOME/.zshrc"; [ -f "$SHELL_RC" ] || touch "$SHELL_RC" ;;
            *)   SHELL_RC="$HOME/.bashrc"; [ -f "$SHELL_RC" ] || SHELL_RC="$HOME/.profile" ;;
        esac

        if [ -n "$SHELL_RC" ] && [ -f "$SHELL_RC" ]; then
            if ! grep -q '\.local/bin' "$SHELL_RC" 2>/dev/null; then
                printf '\n# K.O.D.A.\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$SHELL_RC"
                ok "Added ~/.local/bin to PATH in $(basename "$SHELL_RC")"
            fi
        fi
        export PATH="$BIN_DIR:$PATH"
    fi
}

# ── Run wizard ─────────────────────────────────────────────────────
run_wizard() {
    if [ "$RUN_WIZARD" != "1" ]; then
        info "Skipping wizard (--no-wizard). Run later: koda setup"
        return
    fi
    info "Launching setup wizard..."
    "$VENV_DIR/bin/koda" setup || warn "Wizard exited non-zero — re-run with: koda setup"
}

# ── Success banner ─────────────────────────────────────────────────
print_success() {
    echo ""
    printf "  ${GREEN}${BOLD}✓ K.O.D.A. installed${RESET}\n"
    echo ""
    printf "  ${GOLD}koda${RESET}              Start the REPL\n"
    printf "  ${GOLD}koda setup${RESET}         Re-run wizard\n"
    printf "  ${GOLD}koda doctor${RESET}        Diagnose config\n"
    printf "  ${GOLD}koda update${RESET}        Pull + install the latest release\n"
    printf "  ${GOLD}koda uninstall${RESET}     Remove K.O.D.A. (interactive)\n"
    echo ""

    LOGIN_SHELL="$(basename "${SHELL:-/bin/bash}")"
    if ! command -v koda &>/dev/null; then
        printf "  ${DIM}Restart your shell or run:${RESET}\n"
        if [ "$LOGIN_SHELL" = "zsh" ]; then
            printf "    source ~/.zshrc\n"
        else
            printf "    source ~/.bashrc\n"
        fi
        echo ""
    fi

    printf "  ${DIM}Docs: https://github.com/PabloTheThinker/K.O.D.A.${RESET}\n"
    echo ""
}

# ── Main ───────────────────────────────────────────────────────────
main() {
    echo ""
    printf "  ${GOLD}${BOLD}K.O.D.A.${RESET} ${DIM}— installer${RESET}\n"
    echo ""

    detect_platform
    ensure_git
    ensure_uv
    ensure_python
    fetch_source
    install_koda
    setup_shell
    run_wizard
    print_success
}

main
