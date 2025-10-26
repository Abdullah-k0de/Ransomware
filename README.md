### Action Component
The `client-encrypt.py` file is the encryption component. Save it in the server-type-arch folder in the github (or the payload setup.sh will have to be changed). This also generates the GUI to enter the password

The `client-decrypt-gui.py` is the decryption component that decrypts using the password given by the victim.

The `setup.sh` file has all the commands to download, initialize the environment, and run the attacks. This is the file that will be downloaded by the Rubber Ducky to run the setup in the background process.

The `store-credentials.ts` and `verify-password.ts` are supabase edge functions that has to be deployed and are helper functions for encryption and decryption component respectively.

### Infection Component

The `inject_script.txt` file is the payload script that has the contents of the Rubber Ducky script that needs to be setup manually on the hardware.

The `inject.bin` is the compiled/generated payload that can just copied to the Rubber Ducky to simulate the attack.

### Monitoring Component

#### Audit AppArmor Rules

In File: /etc/audit/rules.d/apparmor.rules:
Write this:
```
-w /etc/apparmor.d/ -p warx -k apparmor
```
Go to:
```
cd /etc/apparmor.d
```
Then:
```
sudo nano /etc/apparmor.d/usr.bin.python3  
```
Write this:
```                                       
#include <tunables/global>

/usr/bin/python3.13 flags=(attach_disconnected, audit) {
  # Log any denied writes anywhere
  audit deny /** w,

  #include <abstractions/base>
  #include <abstractions/python>

  /usr/bin/python3 ix,
  /usr/lib/python3*/** rix,
  /usr/local/lib/python3*/** rix,

  # Allow read/write/execute in home directory, except where denied
  owner @{HOME}/** rwix,

  # Explicitly deny access to protected folder and venv
  deny /home/kali/Desktop/personal_Fa0337/** rwk,
  deny /home/kali/Desktop/venv/** rwk,
}
```
Simulate the attack:
```
 python3 -c "open('/home/kali/Desktop/personal_Fa0337/test.txt','w')"
```
Should give you permission denied (if AppArmor is configured)


To ways to look at the alerts generated:

```
sudo grep 'DENIED' /var/log/audit/audit.log
```
```
sudo tail -f /var/log/audit/audit.log | grep DENIED
```

Website to get the timestamp:
https://www.epochconverter.com/

```
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.python3.13
```

Now, if you do sudo tail -F /var/ossec/logs/alerts/alerts.log

And you simulate the attack, you should see several logs of Possible ransomware detection among other alerts such as Intergrity Checksum changed.


### Detection Component

This component go hand-in-hand with Monitoring and Mitigation Component.

sudo apt update && sudo apt upgrade -y
sudo apt install build-essential gcc make wget tar libevent-dev zlib1g-dev libssl-dev libpcre2-dev -y
sudo nano /var/ossec/etc/rules/local_rules.xml 

curl -so /usr/local/bin/wazuh-install.sh https://packages.wazuh.com/4.7/wazuh-install.sh && \
sudo bash /usr/local/bin/wazuh-install.sh --wazuh-server

curl -so /usr/local/bin/wazuh-install.sh https://packages.wazuh.com/4.7/wazuh-install.sh && \
sudo bash /usr/local/bin/wazuh-install.sh --wazuh-server


 sudo apt install curl -y
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a -i

Include this inside the rules:
```
<directories check_all="yes" realtime="yes">/home/kali/Desktop/personal_Fa0337</directories>
```


LOCAL RULES:
```
<!-- Local rules -->

<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->

<!-- Example -->
<group name="local,syslog,sshd,apparmor,">

  <!--
  Dec 10 01:02:02 host sshd[1234]: Failed none for root>
  -->
  <rule id="200100" level="10">
  <if_sid>554</if_sid>
  <match>encrypted|\.enc|\.locky|\.cry|\.crypt|/\.encry>
  <description>Possible ransomware encryption detected!>
  <mitre><id>T1486</id></mitre>
</rule>



<rule id="200100" level="10">
  <if_sid>550</if_sid>
  <match>encrypted|\.enc|\.locky|\.cry|\.crypt|/.encryp>
  <description>Possible ransomware encryption detected!>
  <mitre><id>T1486</id></mitre>

</rule>


  <!-- Detect mass file modifications within a short pe -->
  <rule id="200101" level="9" frequency="10" timeframe=>
    <if_matched_sid>550</if_matched_sid>
    <description>Multiple files modified in under 60 se>
  </rule>

  <!-- Detect unauthorized system file modification -->
  <rule id="200102" level="12">
    <if_sid>550</if_sid>
    <match>\/bin\/|\/sbin\/|\/usr\/bin\/</match>
    <description>Unauthorized modification of critical >
  </rule>
<!-- ============================================ -->
  <!-- APPARMOR DENIAL RULES (SIMPLIFIED & WORKING) -->
  <!-- ============================================ -->

  <!-- SPECIFIC: venv/include denial (your exact path) -->
  <rule id="200105" level="10">
    <if_sid>200099</if_sid>
    <match>name="/home/kali/Desktop/venv/include"</matc>
    <description>AppArmor blocked venv creation at /hom>
    <mitre><id>T1486</id></mitre>
  </rule>

  <!-- SPECIFIC: personal_Fa0337 folder -->
  <rule id="100001" level="12">
    <if_sid>200099</if_sid>
    <match>name="/home/kali/Desktop/personal_Fa0337"</m>
    <description>CRITICAL: AppArmor blocked access to p>
    <mitre><id>T1562.001</id></mitre>
  </rule>

  <!-- BASE RULE: Catch ALL AppArmor DENIED events (GUA -->
  <rule id="200099" level="7">
    <match>apparmor="DENIED"</match>
    <description>*** AppArmor BLOCKED access - Potentia>
    <group>access_control,pci_dss_10.2.2,gdpr_IV_35.7.d>
  </rule>

  <!-- Python3.13 SPECIFIC denials -->
  <rule id="200103" level="9">
    <if_sid>200099</if_sid>
    <match>profile="/usr/bin/python3.13"</match>
    <description>AppArmor denied Python3.13 access - Ra>
    <mitre><id>T1486</id></mitre>
  </rule>

  <!-- VENV DIRECTORY denials -->
  <rule id="200105" level="10">
    <if_sid>200099</if_sid>
    <match>name="/home/kali/Desktop/venv"</match>
    <description>*** AppArmor blocked venv creation - />
    <mitre><id>T1486</id></mitre>
  </rule>

  <!-- personal_Fa0337 PROTECTED FOLDER denials -->
  <rule id="100001" level="12">
    <if_sid>200099</if_sid>
    <match>name="/home/kali/Desktop/personal_Fa0337"</m>
    <description>*** CRITICAL: AppArmor denied access t>
    <mitre><id>T1562.001</id></mitre>
  </rule>

</group>
```
sudo nano /var/ossec/etc/ossec.conf

Copy the file contents from the github

### Mitigation Component

#### AppArmor

sudo apt update
sudo apt install apparmor apparmor-utils

sudo systemctl enable apparmor
sudo systemctl start apparmor

sudo aa-status

which python3
ls -l /usr/bin/python3

sudo nano /etc/apparmor.d/usr.bin.python3

Then paste this:
```
#include <tunables/global>

/usr/bin/python3.13 flags=(attach_disconnected, audit) {
  # Log any denied writes anywhere
  audit deny /** w,

  #include <abstractions/base>
  #include <abstractions/python>

  /usr/bin/python3 ix,
  /usr/lib/python3*/** rix,
  /usr/local/lib/python3*/** rix,

  # Allow read/write/execute in home directory, except where denied
  owner @{HOME}/** rwix,

  # Explicitly deny access to protected folder and venv
  deny /home/kali/Desktop/personal_Fa0337/** rwk,
  deny /home/kali/Desktop/venv/** rwk,
}
```

sudo apparmor_parser -r /etc/apparmor.d/usr.bin.python3

sudo aa-enforce /usr/bin/python3

Maybe have to restart again:
sudo systemctl restart apparmor

Check:
python3 -c "with open('/home/kali/Desktop/personal_Fa0337/test.txt', 'w') as f: f.write('test')"

or with Rubber Ducky in the setup.log

TO STOP THE APPARMOR: (for the attack to run successfully):
1. sudo aa-teardown
2. sudo systemctl stop apparmor
3. sudo aa-status

Attack will run correctly

TO RE-ENABLE THE APPARMOR:
1. sudo systemctl start apparmor
2. sudo apparmor_parser -r /etc/apparmor.d/*
3. sudo aa-status

#### Defense in Depth

sudo nano /var/ossec/etc/ossec.conf

There are active-response and the command of ransomware active response script file run command

sudo nano /var/ossec/active-response/bin/ransomware-response.sh

Copy the contents of the file from the github

Moreover, there are alert of ransomware detected monitoring in alerts.log (please refer Monitoring component)

#### Backup And Recovery
Backup and Recovery issues are discussed in the report.