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

