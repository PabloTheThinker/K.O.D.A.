#!/usr/bin/env bash
# K.O.D.A. — Kinetic Operative Defense Agent
# One-shot installer. Usage:
#   curl -fsSL https://koda.vektra.dev/install.sh | bash
#
# What this does (and what it does NOT do):
#   - verifies Python >= 3.11
#   - installs K.O.D.A. from PyPI (or from source if you set KODA_SOURCE=1)
#   - runs `koda setup` so you hit the same wizard as a source install
#   - does NOT touch your system Python site-packages without your consent;
#     we use pipx if available, otherwise venv at ~/.koda/.venv.
#
# Env overrides:
#   KODA_REPO          git URL for source install (default: https://github.com/PabloTheThinker/K.O.D.A.)
#   KODA_REF           git ref for source install (default: main)
#   KODA_SOURCE=1      force source install (skip PyPI)
#   KODA_NO_WIZARD=1   skip the post-install wizard
#   KODA_HOME          config dir (default: $HOME/.koda)

set -euo pipefail

GOLD=$'\e[38;5;178m'
GREEN=$'\e[32m'
RED=$'\e[31m'
YELLOW=$'\e[33m'
DIM=$'\e[2m'
BOLD=$'\e[1m'
RESET=$'\e[0m'

KODA_REPO="${KODA_REPO:-https://github.com/PabloTheThinker/K.O.D.A.}"
KODA_REF="${KODA_REF:-main}"
KODA_HOME="${KODA_HOME:-$HOME/.koda}"
KODA_SOURCE="${KODA_SOURCE:-0}"
KODA_NO_WIZARD="${KODA_NO_WIZARD:-0}"

info()  { printf "  %s%s%s\n" "$DIM" "$1" "$RESET"; }
ok()    { printf "  %s✓%s %s\n" "$GREEN" "$RESET" "$1"; }
warn()  { printf "  %s○ %s%s\n" "$YELLOW" "$1" "$RESET"; }
err()   { printf "  %s✗ %s%s\n" "$RED" "$1" "$RESET" 1>&2; }
step()  { printf "\n%s━━━ %s%s\n" "$GOLD" "$1" "$RESET"; }

banner() {
  cat <<BANNER
${GOLD}${BOLD}
  ██╗  ██╗ ██████╗ ██████╗  █████╗
  ██║ ██╔╝██╔═══██╗██╔══██╗██╔══██╗
  █████╔╝ ██║   ██║██║  ██║███████║
  ██╔═██╗ ██║   ██║██║  ██║██╔══██║
  ██║  ██╗╚██████╔╝██████╔╝██║  ██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝${RESET}
  ${BOLD}Kinetic Operative Defense Agent${RESET}
  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}
  ${DIM}Vektra Industries • Open Source • AI Security${RESET}
BANNER
}

check_python() {
  step "Checking Python"
  local candidates=("python3.13" "python3.12" "python3.11" "python3")
  for p in "${candidates[@]}"; do
    if command -v "$p" >/dev/null 2>&1; then
      local v
      v=$("$p" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))' 2>/dev/null || echo "")
      if "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
        PY="$p"
        ok "$p → $v"
        return 0
      fi
    fi
  done
  err "Python 3.11+ not found."
  info "install from: https://www.python.org/downloads/"
  exit 1
}

pick_installer() {
  step "Picking install method"
  if command -v pipx >/dev/null 2>&1; then
    INSTALLER="pipx"
    ok "pipx found — will install as isolated app"
    return
  fi
  INSTALLER="venv"
  VENV_DIR="$KODA_HOME/.venv"
  ok "using venv at $VENV_DIR"
}

install_from_pypi() {
  step "Installing K.O.D.A. from PyPI"
  if [[ "$INSTALLER" == "pipx" ]]; then
    pipx install --force koda || {
      warn "PyPI install via pipx failed; falling back to source install"
      install_from_source
      return
    }
    ok "pipx installed koda"
  else
    mkdir -p "$KODA_HOME"
    "$PY" -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip >/dev/null
    if ! "$VENV_DIR/bin/pip" install koda; then
      warn "PyPI install failed; falling back to source install"
      install_from_source
      return
    fi
    ok "koda installed into $VENV_DIR"
  fi
}

install_from_source() {
  step "Installing K.O.D.A. from source ($KODA_REPO @ $KODA_REF)"
  local tmp
  tmp="$(mktemp -d -t koda-install-XXXXXX)"
  trap 'rm -rf "$tmp"' RETURN
  if ! command -v git >/dev/null 2>&1; then
    err "git required for source install. install git, or set KODA_SOURCE=0."
    exit 1
  fi
  git clone --depth 1 --branch "$KODA_REF" "$KODA_REPO" "$tmp/koda" >/dev/null 2>&1 || {
    err "git clone failed: $KODA_REPO @ $KODA_REF"
    exit 1
  }
  if [[ "$INSTALLER" == "pipx" ]]; then
    pipx install --force "$tmp/koda"
    ok "pipx installed koda from source"
  else
    mkdir -p "$KODA_HOME"
    "$PY" -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install --upgrade pip >/dev/null
    "$VENV_DIR/bin/pip" install "$tmp/koda"
    ok "koda installed into $VENV_DIR"
  fi
}

link_binary() {
  step "Linking koda command"
  local target
  if [[ "$INSTALLER" == "pipx" ]]; then
    target="$(command -v koda || true)"
    if [[ -n "$target" ]]; then
      ok "koda on PATH → $target"
      return
    fi
    warn "koda not on PATH — run: pipx ensurepath"
    return
  fi
  target="$VENV_DIR/bin/koda"
  if [[ ! -x "$target" ]]; then
    err "koda binary missing at $target"
    exit 1
  fi
  local bin_dir="$HOME/.local/bin"
  mkdir -p "$bin_dir"
  ln -sf "$target" "$bin_dir/koda"
  ok "symlinked $bin_dir/koda → $target"
  case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) warn "$bin_dir is not on PATH. add this to your shell rc:"
       info "  export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
  esac
}

run_wizard() {
  if [[ "$KODA_NO_WIZARD" == "1" ]]; then
    step "Skipping wizard (KODA_NO_WIZARD=1)"
    info "run it later with: koda setup"
    return
  fi
  step "Running setup wizard"
  if ! command -v koda >/dev/null 2>&1; then
    warn "koda not on PATH yet — run the wizard manually:"
    info "  koda setup"
    return
  fi
  koda setup || warn "wizard exited non-zero — re-run with: koda setup"
}

done_msg() {
  cat <<EOF

${GOLD}━━━ Done${RESET}
  start the REPL:  ${BOLD}koda${RESET}
  re-run wizard:   ${BOLD}koda setup${RESET}
  diagnose:        ${BOLD}koda doctor${RESET}
  docs:            ${DIM}${KODA_REPO}${RESET}

EOF
}

main() {
  banner
  check_python
  pick_installer
  if [[ "$KODA_SOURCE" == "1" ]]; then
    install_from_source
  else
    install_from_pypi
  fi
  link_binary
  run_wizard
  done_msg
}

main "$@"
