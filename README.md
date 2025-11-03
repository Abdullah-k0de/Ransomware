# Ransomware Attack Simulation & Defense-in-Depth System  
**Kali Linux Setup Guide**  
A complete, step-by-step README for simulating a **ransomware attack** using a **USB Rubber Ducky**, **AppArmor confinement**, **Wazuh FIM**, **custom rules**, **Supabase edge functions**, and **active response mitigation**.

> **Target Environment**: Kali Linux (2024+)  
> **User**: `kali` (default user)  
> **Protected Directory**: `/home/kali/Desktop/personal_Fa0337`  
> **Virtual Environment Path**: `/home/kali/Desktop/venv`

---

## Project Structure
server-type-arch/

├── client-encrypt.py          # Encryption GUI (attacker)

├── client-decrypt-gui.py      # Decryption GUI (victim)

├── setup.sh                   # Rubber Ducky background payload

├── store-credentials.ts       # Supabase: store encrypted key

├── verify-password.ts         # Supabase: verify ransom password

├── inject_script.txt          # Raw Ducky script

├── inject.bin                 # Compiled payload (copy to Ducky)

└── ransomware-response.sh     # Wazuh active response (kill + log)


## Prerequisites (Install First!)

> **Run these commands before anything else**

```
sudo apt update && sudo apt upgrade -y
sudo apt install -y build-essential gcc make wget tar \
    libevent-dev zlib1g-dev libssl-dev libpcre2-dev \
    apparmor apparmor-utils auditd audispd-plugins \
    python3 python3-pip python3-venv curl git nano
```
You must have python3.13 (or symlink /usr/bin/python3 → python3.13)
```
which python3
python3 --version  # Should show 3.13+
```

## 1. Action Component (Encryption & Decryption)
Save Files in server-type-arch/
```
mkdir -p ~/server-type-arch
cd ~/server-type-arch
```
Download or copy the following files from your GitHub repo:

- `client-encrypt.py`
- `client-decrypt-gui.py`
- `setup.sh`
- `store-credentials.ts`
- `verify-password.ts`


Note: setup.sh assumes files are in ~/server-type-arch/.
If you move them, edit setup.sh accordingly.


Deploy Supabase Edge Functions

Install Supabase CLI (if not done):
`npm install -g @supabase/cli`

Login & deploy:
```
supabase login
supabase functions deploy store-credentials --project-ref YOUR_PROJECT_REF
supabase functions deploy verify-password --project-ref YOUR_PROJECT_REF
```


Replace YOUR_PROJECT_REF with your actual Supabase project ID.


## 2. Infection Component (Rubber Ducky)
Option A: Use Precompiled Payload
```cp inject.bin /media/kali/USBDISK/ ```
→ Eject USB → Insert into victim machine
Option B: Generate Your Own (Advanced)

Use Hak5 Payload Studio or duckencoder
Paste contents of inject_script.txt
Compile → inject.bin


## 3. Monitoring Component
Enable Auditd & AppArmor Logging
```sudo nano /etc/audit/rules.d/apparmor.rules```
Paste:
```-w /etc/apparmor.d/ -p warx -k apparmor```
Reload rules:
```sudo augenrules --load
sudo systemctl restart auditd
```

Create AppArmor Profile for Python3
```sudo nano /etc/apparmor.d/usr.bin.python3```
Paste:
```
#include <tunables/global>

/usr/bin/python3.13 flags=(attach_disconnected, audit) {
  audit deny /** w,

  #include <abstractions/base>
  #include <abstractions/python>

  /usr/bin/python3 ix,
  /usr/lib/python3*/** rix,
  /usr/local/lib/python3*/** rix,

  owner @{HOME}/** rwix,

  deny /home/kali/Desktop/personal_Fa0337/** rwk,
  deny /home/kali/Desktop/venv/** rwk,
}
```
Load profile:
```
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.python3.13
sudo aa-enforce /usr/bin/python3.13
sudo systemctl restart apparmor
```

Test AppArmor (Should Fail)
```python3 -c "open('/home/kali/Desktop/personal_Fa0337/test.txt','w').write('test')"```
Expected: Permission denied
Check logs:
```sudo grep 'DENIED' /var/log/audit/audit.log
sudo tail -f /var/log/audit/audit.log | grep DENIED
```
Use https://www.epochconverter.com to decode timestamps.

## 4. Detection Component (Wazuh)
Install Wazuh Agent + Manager (All-in-One)
```curl -so wazuh-install.sh https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

This installs Wazuh manager + agent on the same machine.


Configure FIM (File Integrity Monitoring)
```sudo nano /var/ossec/etc/ossec.conf```
Add inside <syscheck>:
```
<directories check_all="yes" realtime="yes">/home/kali/Desktop/personal_Fa0337</directories>
```
Restart Wazuh:
```
sudo systemctl restart wazuh-manager
```

Add Local Detection Rules
```
sudo nano /var/ossec/etc/rules/local_rules.xml
```
Paste full content (replace any existing <group>):
```
<!-- Local rules -->
<group name="local,syslog,sshd,apparmor,ransomware">

  <!-- Ransomware filename patterns -->
  <rule id="200100" level="10">
    <if_sid>550</if_sid>
    <match>encrypted|\.enc|\.locky|\.cry|\.crypt|\.encry</match>
    <description>Possible ransomware encryption detected!</description>
    <mitre><id>T1486</id></mitre>
  </rule>

  <!-- Mass modification in 60s -->
  <rule id="200101" level="9" frequency="10" timeframe="60">
    <if_matched_sid>550</if_matched_sid>
    <description>Multiple files modified in under 60 seconds - Possible ransomware</description>
  </rule>

  <!-- Critical system files -->
  <rule id="200102" level="12">
    <if_sid>550</if_sid>
    <match>\/bin\/|\/sbin\/|\/usr\/bin\/</match>
    <description>Unauthorized modification of critical system binaries</description>
  </rule>

  <!-- AppArmor: Base DENIED catcher -->
  <rule id="200099" level="7">
    <match>apparmor="DENIED"</match>
    <description>*** AppArmor BLOCKED access - Potential ransomware containment</description>
    <group>access_control,pci_dss_10.2.2,gdpr_IV_35.7.d</group>
  </rule>

  <!-- Python3.13 denials -->
  <rule id="200103" level="9">
    <if_sid>200099</if_sid>
    <match>profile="/usr/bin/python3.13"</match>
    <description>AppArmor denied Python3.13 access - Ransomware blocked</description>
    <mitre><id>T1486</id></mitre>
  </rule>

  <!-- venv denial -->
  <rule id="200105" level="10">
    <if_sid>200099</if_sid>
    <match>name="/home/kali/Desktop/venv"</match>
    <description>*** AppArmor blocked venv creation - Attack prevented</description>
    <mitre><id>T1486</id></mitre>
  </rule>

  <!-- personal_Fa0337 folder access denied -->
  <rule id="100001" level="12">
    <if_sid>200099</if_sid>
    <match>name="/home/kali/Desktop/personal_Fa0337"</match>
    <description>*** CRITICAL: AppArmor denied access to protected user data</description>
    <mitre><id>T1562.001</id></mitre>
  </rule>

</group>
```
Reload rules:
```
sudo /var/ossec/bin/wazuh-control restart
```
Monitor Alerts in Real-Time
```
sudo tail -f /var/ossec/logs/alerts/alerts.log | grep -E "ransomware|DENIED|AppArmor"
```
You should see:

Possible ransomware encryption detected!
Integrity checksum changed
AppArmor BLOCKED access


## 5. Mitigation Component
AppArmor Hardening (Re-Enable)
```
sudo systemctl start apparmor
sudo apparmor_parser -r /etc/apparmor.d/*
sudo aa-enforce /usr/bin/python3.13
sudo aa-status
```

### Defense in Depth

Active Response: Kill Ransomware Process
```
sudo nano /var/ossec/active-response/bin/ransomware-response.sh
```
Paste from GitHub (example below):
```
#!/bin/bash
# Wazuh Active Response: Kill ransomware on detection

ACTION=$1
USER=$2
IP=$3
ALERTID=$4
RULEID=$5

# Only act on 'add' (trigger)
[ "$ACTION" != "add" ] && exit 0

# Extract PID from alert
PID=$(grep -oP '(?<=pid=)[0-9]+' /var/ossec/logs/alerts/alerts.json | tail -1)

if [[ -n "$PID" && "$PID" =~ ^[0-9]+$ ]]; then
  kill -9 "$PID" 2>/dev/null
  echo "Ransomware process (PID: $PID) terminated." >> /var/ossec/logs/active-responses.log
fi

exit 0
```
Make executable:
```
sudo chmod +x /var/ossec/active-response/bin/ransomware-response.sh
sudo chown root:root /var/ossec/active-response/bin/ransomware-response.sh
```
Enable in ossec.conf:
```
<command>
  <name>kill-ransomware</name>
  <executable>ransomware-response.sh</executable>
  <expect>srcip</expect>
</command>

<active-response>
  <command>kill-ransomware</command>
  <location>local</location>
  <rules_id>100001,200100,200101</rules_id>
  <timeout>0</timeout>
</active-response>
```
Restart:
```
sudo systemctl restart wazuh-manager
```
Temporarily Disable AppArmor (For Attack Demo)

Only for simulation!

```
sudo aa-teardown
sudo systemctl stop apparmor
```
→ Now setup.sh will encrypt files

Re-Enable Defenses
```
sudo systemctl start apparmor
sudo apparmor_parser -r /etc/apparmor.d/*
sudo aa-status
```

### Backup & Recovery

Discussed in full report.

Test Full Attack (With Defenses OFF)

Disable AppArmor
Insert Rubber Ducky (inject.bin)
Watch:
tail -f ~/setup.log

→ Files encrypted → GUI demands password

Test Full Defense (With AppArmor + Wazuh ON)

Re-enable AppArmor
Run attack
Observe:

Permission denied
Wazuh alerts
Process killed
No .enc files created

Troubleshooting


Issue Fix 
apparmor_parser: no such file 
sudo apt install apparmor-utils

python3: command not found
sudo ln -s /usr/bin/python3.13 /usr/bin/python3

No Wazuh alerts
sudo systemctl status wazuh-manager

Active response not firing
Check /var/ossec/logs/active-responses.log

## Video
![Demo Video Demonstration](media/video.mp4)

References
- Wazuh Docs: https://documentation.wazuh.com
- AppArmor: https://gitlab.com/apparmor/apparmor
- Hak5 Rubber Ducky: https://hak5.org
- Supabase Edge Functions: https://supabase.com/docs/guides/functions
