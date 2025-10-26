#!/bin/bash
# ransomware-response.sh - Kills process, quarantines file, alerts admin

LOG_FILE="/var/ossec/logs/active-responses.log"
QUARANTINE_DIR="/tmp/quarantine"
ADMIN_EMAIL="bogusforanything@gmail.com"

# Read input from Wazuh (JSON alert)
read INPUT
echo "$INPUT" > /tmp/ar_input.json

# Extract relevant fields (requires jq installed)
FILE_PATH=$(jq -r '.parameters.alert.syscheck.path // ""' /tmp/ar_input.json)
PID=$(jq -r '.parameters.alert.data.apparmor.pid // ""' /tmp/ar_input.json)  # From AppArmor if available
PROCESS_NAME=$(jq -r '.parameters.alert.data.apparmor.comm // ""' /tmp/ar_input.json)

# Log start
echo "Active response triggered for file: $FILE_PATH, PID: $PID" >> $LOG_FILE

# Step 1: Terminate process if PID available
if [ ! -z "$PID" ]; then
  kill -9 $PID 2>/dev/null
  echo "Terminated process $PROCESS_NAME (PID: $PID)" >> $LOG_FILE
fi

# Step 2: Quarantine file if changed
if [ ! -z "$FILE_PATH" ] && [ -f "$FILE_PATH" ]; then
  mkdir -p $QUARANTINE_DIR
  mv "$FILE_PATH" $QUARANTINE_DIR/
  echo "Quarantined file: $FILE_PATH" >> $LOG_FILE
fi

# Step 3: Send email alert (requires mailx or similar)
echo "Ransomware alert: Suspicious activity on $FILE_PATH. Process terminated." | mail -s "Wazuh Ransomware Alert">

# Clean up
rm /tmp/ar_input.json
