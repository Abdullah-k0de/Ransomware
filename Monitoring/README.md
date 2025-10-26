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


