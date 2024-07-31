# Active Directory - Enumeration

## Using BloodHound

Use the correct collector:

* [BloodHoundAD/AzureHound](https://github.com/BloodHoundAD/AzureHound) for Azure Active Directory
* [BloodHoundAD/SharpHound](https://github.com/BloodHoundAD/SharpHound) for local Active Directory (C# collector)
* [FalconForceTeam/SOAPHound](https://github.com/FalconForceTeam/SOAPHound) for local Active Directory (C# collector using ADWS)
* [NH-RED-TEAM/RustHound](https://github.com/NH-RED-TEAM/RustHound) for local Active Directory (Rust collector)
* [fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py) for local Active Directory (Python collector)
* [coffeegist/bofhound](https://github.com/coffeegist/bofhound) for local Active Directory  (Generate BloodHound compatible JSON from logs written by ldapsearch BOF, pyldapsearch and Brute Ratel's LDAP Sentinel)

**Examples**:

* Use [BloodHoundAD/AzureHound](https://github.com/BloodHoundAD/AzureHound) (more info: [Cloud - Azure Pentest](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md#azure-recon-tools))

* Use [BloodHoundAD/SharpHound.exe](https://github.com/BloodHoundAD/BloodHound) - run the collector on the machine using SharpHound.exe
  ```powershell
  .\SharpHound.exe -c all -d active.htb --searchforest
  .\SharpHound.exe -c all,GPOLocalGroup # all collection doesn't include GPOLocalGroup by default
  .\SharpHound.exe --CollectionMethod DCOnly # only collect from the DC, doesn't query the computers (more stealthy)

  .\SharpHound.exe -c all --LdapUsername <UserName> --LdapPassword <Password> --JSONFolder <PathToFile>
  .\SharpHound.exe -c all --LdapUsername <UserName> --LdapPassword <Password> --domaincontroller 10.10.10.100 -d active.htb

  .\SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\Windows\Temp --prettyprint --randomfilenames --collectallproperties --throttle 10000 --jitter 23  --outputprefix internalallthething
  ```
* Use [BloodHoundAD/SharpHound.ps1](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1) - run the collector on the machine using Powershell
  ```powershell
  Invoke-BloodHound -SearchForest -CSVFolder C:\Users\Public
  Invoke-BloodHound -CollectionMethod All  -LDAPUser <UserName> -LDAPPass <Password> -OutputDirectory <PathToFile>
  ```
* Use [ly4k/Certipy](https://github.com/ly4k/Certipy) to collect certificates data
  ```ps1
  certipy find 'corp.local/john:Passw0rd@dc.corp.local' -bloodhound
  certipy find 'corp.local/john:Passw0rd@dc.corp.local' -old-bloodhound
  certipy find 'corp.local/john:Passw0rd@dc.corp.local' -vulnerable -hide-admins -username user@domain -password Password123
  ```
* Use [NH-RED-TEAM/RustHound](https://github.com/OPENCYBER-FR/RustHound)
  ```ps1
  # Windows with GSSAPI session
  rusthound.exe -d domain.local --ldapfqdn domain
  # Windows/Linux simple bind connection username:password
  rusthound.exe -d domain.local -u user@domain.local -p Password123 -o output -z
  # Linux with username:password and ADCS module for @ly4k BloodHound version
  rusthound -d domain.local -u 'user@domain.local' -p 'Password123' -o /tmp/adcs --adcs -z
  ```
* Use [FalconForceTeam/SOAPHound](https://github.com/FalconForceTeam/SOAPHound)
  ```ps1
  --buildcache: Only build cache and not perform further actions
  --bhdump: Dump BloodHound data
  --certdump: Dump AD Certificate Services (ADCS) data
  --dnsdump: Dump AD Integrated DNS data

  SOAPHound.exe --buildcache -c c:\temp\cache.txt
  SOAPHound.exe -c c:\temp\cache.txt --bhdump -o c:\temp\bloodhound-output
  SOAPHound.exe -c c:\temp\cache.txt --bhdump -o c:\temp\bloodhound-output --autosplit --threshold 1000
  SOAPHound.exe -c c:\temp\cache.txt --certdump -o c:\temp\bloodhound-output
  SOAPHound.exe --dnsdump -o c:\temp\dns-output
  ```
* Use [fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py)
  ```
  pip install bloodhound
  bloodhound-python -d lab.local -u rsmith -p Winter2017 -gc LAB2008DC01.lab.local -c all
  ```
* Use [c3c/ADExplorerSnapshot.py](https://github.com/c3c/ADExplorerSnapshot.py) to query data from SysInternals/ADExplorer snapshot  (ADExplorer remains a legitimate binary signed by Microsoft, avoiding detection with security solutions).
  ```py
  ADExplorerSnapshot.py <snapshot path> -o <*.json output folder path>
  ```

Then import the zip/json files into the Neo4J database and query them.

```powershell
root@payload$ apt install bloodhound 

# start BloodHound and the database
root@payload$ neo4j console
# or use docker
root@payload$ docker run -itd -p 7687:7687 -p 7474:7474 --env NEO4J_AUTH=neo4j/bloodhound -v $(pwd)/neo4j:/data neo4j:4.4-community

root@payload$ ./bloodhound --no-sandbox
Go to http://127.0.0.1:7474, use db:bolt://localhost:7687, user:neo4J, pass:neo4j
```

NOTE: Currently BloodHound Community Edition is still a work in progress, it is highly recommended to stay on the original [BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound/) version. 

```ps1
git clone https://github.com/SpecterOps/BloodHound
cd examples/docker-compose/
cat docker-compose.yml | docker compose -f - up
# UI: http://localhost:8080/ui/login
# Username: admin
# Password: see your Docker logs
```

You can add some custom queries like :

* [Bloodhound-Custom-Queries from @hausec](https://github.com/hausec/Bloodhound-Custom-Queries/blob/master/customqueries.json)
* [BloodHoundQueries from CompassSecurity](https://github.com/CompassSecurity/BloodHoundQueries/blob/master/customqueries.json)
* [BloodHound Custom Queries from Exegol - @ShutdownRepo](https://raw.githubusercontent.com/ThePorgs/Exegol-images/main/sources/assets/bloodhound/customqueries.json)
* [Certipy BloodHound Custom Queries from ly4k](https://github.com/ly4k/Certipy/blob/main/customqueries.json)

Replace the customqueries.json file located at `/home/username/.config/bloodhound/customqueries.json` or `C:\Users\USERNAME\AppData\Roaming\BloodHound\customqueries.json`.


## Using PowerView
  
- **Get Current Domain:** `Get-NetDomain`
- **Enum Other Domains:** `Get-NetDomain -Domain <DomainName>`
- **Get Domain SID:** `Get-DomainSID`
- **Get Domain Policy:** 
  ```powershell
  Get-DomainPolicy

  #Will show us the policy configurations of the Domain about system access or kerberos
  (Get-DomainPolicy)."system access"
  (Get-DomainPolicy)."kerberos policy"
  ```
- **Get Domain Controlers:** 
  ```powershell
  Get-NetDomainController
  Get-NetDomainController -Domain <DomainName>
  ```
- **Enumerate Domain Users:** 
  ```powershell
  Get-NetUser
  Get-NetUser -SamAccountName <user> 
  Get-NetUser | select cn
  Get-UserProperty

  #Check last password change
  Get-UserProperty -Properties pwdlastset

  #Get a specific "string" on a user's attribute
  Find-UserField -SearchField Description -SearchTerm "wtver"
  
  #Enumerate user logged on a machine
  Get-NetLoggedon -ComputerName <ComputerName>
  
  #Enumerate Session Information for a machine
  Get-NetSession -ComputerName <ComputerName>
  
  #Enumerate domain machines of the current/specified domain where specific users are logged into
  Find-DomainUserLocation -Domain <DomainName> | Select-Object UserName, SessionFromName
  ```
- **Enum Domain Computers:** 
  ```powershell
  Get-NetComputer -FullData
  Get-DomainGroup

  #Enumerate Live machines 
  Get-NetComputer -Ping
  ```
- **Enum Groups and Group Members:**
  ```powershell
  Get-NetGroupMember -GroupName "<GroupName>" -Domain <DomainName>
  
  #Enumerate the members of a specified group of the domain
  Get-DomainGroup -Identity <GroupName> | Select-Object -ExpandProperty Member
  
  #Returns all GPOs in a domain that modify local group memberships through Restricted Groups or Group Policy Preferences
  Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName
  ```
- **Enumerate Shares**
  ```powershell
  #Enumerate Domain Shares
  Find-DomainShare
  
  #Enumerate Domain Shares the current user has access
  Find-DomainShare -CheckShareAccess
  ```
- **Enum Group Policies:** 
  ```powershell
  Get-NetGPO

  # Shows active Policy on specified machine
  Get-NetGPO -ComputerName <Name of the PC>
  Get-NetGPOGroup

  #Get users that are part of a Machine's local Admin group
  Find-GPOComputerAdmin -ComputerName <ComputerName>
  ```
- **Enum OUs:** 
  ```powershell
  Get-NetOU -FullData 
  Get-NetGPO -GPOname <The GUID of the GPO>
  ```
- **Enum ACLs:** 
  ```powershell
  # Returns the ACLs associated with the specified account
  Get-ObjectAcl -SamAccountName <AccountName> -ResolveGUIDs
  Get-ObjectAcl -ADSprefix 'CN=Administrator, CN=Users' -Verbose

  #Search for interesting ACEs
  Invoke-ACLScanner -ResolveGUIDs

  #Check the ACLs associated with a specified path (e.g smb share)
  Get-PathAcl -Path "\\Path\Of\A\Share"
  ```
- **Enum Domain Trust:** 
  ```powershell
  Get-NetDomainTrust
  Get-NetDomainTrust -Domain <DomainName>
  ```
- **Enum Forest Trust:** 
  ```powershell
  Get-NetForestDomain
  Get-NetForestDomain Forest <ForestName>

  #Domains of Forest Enumeration
  Get-NetForestDomain
  Get-NetForestDomain Forest <ForestName>

  #Map the Trust of the Forest
  Get-NetForestTrust
  Get-NetDomainTrust -Forest <ForestName>
  ```
- **User Hunting:** 
  ```powershell
  #Finds all machines on the current domain where the current user has local admin access
  Find-LocalAdminAccess -Verbose

  #Find local admins on all machines of the domain:
  Invoke-EnumerateLocalAdmin -Verbose

  #Find computers were a Domain Admin OR a specified user has a session
  Invoke-UserHunter
  Invoke-UserHunter -GroupName "RDPUsers"
  Invoke-UserHunter -Stealth

  #Confirming admin access:
  Invoke-UserHunter -CheckAccess
  ```


## Using AD Module

- **Get Current Domain:** `Get-ADDomain`
- **Enum Other Domains:** `Get-ADDomain -Identity <Domain>`
- **Get Domain SID:** `Get-DomainSID`
- **Get Domain Controlers:** 

  ```powershell
  Get-ADDomainController
  Get-ADDomainController -Identity <DomainName>
  ```
  
- **Enumerate Domain Users:** 
  ```powershell
  Get-ADUser -Filter * -Identity <user> -Properties *

  #Get a specific "string" on a user's attribute
  Get-ADUser -Filter 'Description -like "*wtver*"' -Properties Description | select Name, Description
  ```
- **Enum Domain Computers:** 
  ```powershell
  Get-ADComputer -Filter * -Properties *
  Get-ADGroup -Filter * 
  ```
- **Enum Domain Trust:** 
  ```powershell
  Get-ADTrust -Filter *
  Get-ADTrust -Identity <DomainName>
  ```
- **Enum Forest Trust:** 
  ```powershell
  Get-ADForest
  Get-ADForest -Identity <ForestName>

  #Domains of Forest Enumeration
  (Get-ADForest).Domains
  ```
 - **Enum Local AppLocker Effective Policy:**
 ```powershell
 Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
 ```


## User Hunting

Sometimes you need to find a machine where a specific user is logged in.    
You can remotely query every machines on the network to get a list of the users's sessions.

* netexec
  ```ps1
  nxc smb 10.10.10.0/24 -u Administrator -p 'P@ssw0rd' --sessions
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


## RID cycling

Enumerate users from the Domain Controllers.

* Using `netexec`
  ```ps1
  netexec smb 10.10.11.231 -u guest -p '' --rid-brute 10000 --log rid-brute.txt
  SMB         10.10.11.231    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:rebound.htb) (signing:True) (SMBv1:False)
  SMB         10.10.11.231    445    DC01             [+] rebound.htb\guest: 
  SMB         10.10.11.231    445    DC01             498: rebound\Enterprise Read-only Domain Controllers (SidTypeGroup)
  SMB         10.10.11.231    445    DC01             500: rebound\Administrator (SidTypeUser)
  SMB         10.10.11.231    445    DC01             501: rebound\Guest (SidTypeUser)
  SMB         10.10.11.231    445    DC01             502: rebound\krbtgt (SidTypeUser)
  ```

* Using Impacket script [lookupsid.py](https://github.com/fortra/impacket/blob/master/examples/lookupsid.py)
  ```ps1
  lookupsid.py -no-pass 'guest@rebound.htb' 20000
  ```


## Other Interesting Commands

- **Find Domain Controllers**
  ```ps1
  nslookup domain.com
  nslookup -type=srv _ldap._tcp.dc._msdcs.<domain>.com
  nltest /dclist:domain.com
  Get-ADDomainController -filter * | Select-Object name
  gpresult /r
  $Env:LOGONSERVER 
  echo %LOGONSERVER%
  ```


## References

* [Explain like I’m 5: Kerberos - Apr 2, 2013 - @roguelynn](https://www.roguelynn.com/words/explain-like-im-5-kerberos/)
* [Pen Testing Active Directory Environments - Part I: Introduction to netexec (and PowerView)](https://blog.varonis.com/pen-testing-active-directory-environments-part-introduction-netexec-powerview/)
* [Pen Testing Active Directory Environments - Part II: Getting Stuff Done With PowerView](https://blog.varonis.com/pen-testing-active-directory-environments-part-ii-getting-stuff-done-with-powerview/)
* [Pen Testing Active Directory Environments - Part III:  Chasing Power Users](https://blog.varonis.com/pen-testing-active-directory-environments-part-iii-chasing-power-users/)
* [Pen Testing Active Directory Environments - Part IV: Graph Fun](https://blog.varonis.com/pen-testing-active-directory-environments-part-iv-graph-fun/)
* [Pen Testing Active Directory Environments - Part V: Admins and Graphs](https://blog.varonis.com/pen-testing-active-directory-v-admins-graphs/)
* [Pen Testing Active Directory Environments - Part VI: The Final Case](https://blog.varonis.com/pen-testing-active-directory-part-vi-final-case/)
* [Attacking Active Directory: 0 to 0.9 - Eloy Pérez González - 2021/05/29](https://zer1t0.gitlab.io/posts/attacking_ad/)
* [Fun with LDAP, Kerberos (and MSRPC) in AD Environments](https://speakerdeck.com/ropnop/fun-with-ldap-kerberos-and-msrpc-in-ad-environments)
* [Penetration Testing Active Directory, Part I - March 5, 2019 - Hausec](https://hausec.com/2019/03/05/penetration-testing-active-directory-part-i/)
* [Penetration Testing Active Directory, Part II - March 12, 2019 - Hausec](https://hausec.com/2019/03/12/penetration-testing-active-directory-part-ii/)
* [Using bloodhound to map the user network - Hausec](https://hausec.com/2017/10/26/using-bloodhound-to-map-the-user-network/)
* [PowerView 3.0 Tricks - HarmJ0y](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
* [SOAPHound - tool to collect Active Directory data via ADWS - Nikos Karouzos - 01/26/204](https://medium.com/falconforce/soaphound-tool-to-collect-active-directory-data-via-adws-165aca78288c)
* [Training - Attacking and Defending Active Directory Lab - Altered Security](https://www.alteredsecurity.com/adlab)