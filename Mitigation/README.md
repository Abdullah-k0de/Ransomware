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