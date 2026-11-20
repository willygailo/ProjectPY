#!/usr/bin/env bash
set -euo pipefail

# Kali Linux / Debian installer for S1shell
# Usage: ./scripts/install-kali.sh [--dev]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEV_MODE=false

for arg in "$@"; do
  case "${arg}" in
    --dev)
      DEV_MODE=true
      ;;
    -h|--help)
      echo "Usage: $0 [--dev]"
      echo "  --dev   Create .venv inside repository and install editable with dev dependencies"
      exit 0
      ;;
    *)
      echo "Unknown option: ${arg}" >&2
      exit 1
      ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 is required." >&2
  exit 1
fi

python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit(f"Python >= 3.10 required; found {sys.version}")
PY

if [[ "${EUID}" -eq 0 ]]; then
  SUDO=""
else
  SUDO="sudo"
fi

echo "[*] Installing Kali system prerequisites..."
${SUDO} apt-get update
${SUDO} apt-get install -y python3 python3-venv python3-pip pipx

if [[ "${DEV_MODE}" == "true" ]]; then
  echo "[*] Setting up editable development environment in ${REPO_ROOT}/.venv..."
  python3 -m venv "${REPO_ROOT}/.venv"
  "${REPO_ROOT}/.venv/bin/python" -m pip install --upgrade pip
  "${REPO_ROOT}/.venv/bin/pip" install -e "${REPO_ROOT}[dev]"
  "${REPO_ROOT}/.venv/bin/s1shell" --version
  "${REPO_ROOT}/.venv/bin/s1shell" doctor
  echo "[+] Development environment ready. Activate with: source ${REPO_ROOT}/.venv/bin/activate"
else
  echo "[*] Ensuring pipx path is initialized..."
  pipx ensurepath || true
  echo "[*] Installing/upgrading S1shell via pipx from ${REPO_ROOT}..."
  pipx install --force "${REPO_ROOT}"
  echo "[*] Verifying S1shell installation..."
  s1shell --version
  s1shell doctor
  echo "[+] S1shell installation complete."
fi
