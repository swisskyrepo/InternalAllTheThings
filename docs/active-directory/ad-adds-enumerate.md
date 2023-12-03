# Active Directory - Enumeration

## Using BloodHound

Use the correct collector
* AzureHound for Azure Active Directory
* SharpHound for local Active Directory
* RustHound for local Active Directory

* use [BloodHoundAD/AzureHound](https://github.com/BloodHoundAD/AzureHound) (more info: [Cloud - Azure Pentest](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Cloud%20-%20Azure%20Pentest.md#azure-recon-tools))

* use [BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)
  ```powershell
  # run the collector on the machine using SharpHound.exe
  # https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe
  # /usr/lib/bloodhound/resources/app/Collectors/SharpHound.exe
  .\SharpHound.exe -c all -d active.htb --searchforest
  .\SharpHound.exe -c all,GPOLocalGroup # all collection doesn't include GPOLocalGroup by default
  .\SharpHound.exe --CollectionMethod DCOnly # only collect from the DC, doesn't query the computers (more stealthy)

  .\SharpHound.exe -c all --LdapUsername <UserName> --LdapPassword <Password> --JSONFolder <PathToFile>
  .\SharpHound.exe -c all --LdapUsername <UserName> --LdapPassword <Password> --domaincontroller 10.10.10.100 -d active.htb
  .\SharpHound.exe -c all,GPOLocalGroup --outputdirectory C:\Windows\Temp --randomizefilenames --prettyjson --nosavecache --encryptzip --collectallproperties --throttle 10000 --jitter 23

  # or run the collector on the machine using Powershell
  # https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.ps1
  # /usr/lib/bloodhound/resources/app/Collectors/SharpHound.ps1
  Invoke-BloodHound -SearchForest -CSVFolder C:\Users\Public
  Invoke-BloodHound -CollectionMethod All  -LDAPUser <UserName> -LDAPPass <Password> -OutputDirectory <PathToFile>

  # or remotely via BloodHound Python
  # https://github.com/fox-it/BloodHound.py
  pip install bloodhound
  bloodhound-python -d lab.local -u rsmith -p Winter2017 -gc LAB2008DC01.lab.local -c all
  
  # or locally/remotely from an ADExplorer snapshot from SysInternals (ADExplorer remains a legitimate binary signed by Microsoft, avoiding detection with security solutions)
  # https://github.com/c3c/ADExplorerSnapshot.py
  pip3 install --user .
  ADExplorerSnapshot.py <snapshot path> -o <*.json output folder path>
  ```
* Collect more data for certificates exploitation using Certipy
  ```ps1
  certipy find 'corp.local/john:Passw0rd@dc.corp.local' -bloodhound
  certipy find 'corp.local/john:Passw0rd@dc.corp.local' -old-bloodhound
  certipy find 'corp.local/john:Passw0rd@dc.corp.local' -vulnerable -hide-admins -username user@domain -password Password123
  ```
* use [OPENCYBER-FR/RustHound](https://github.com/OPENCYBER-FR/RustHound)
  ```ps1
  # Windows with GSSAPI session
  rusthound.exe -d domain.local --ldapfqdn domain
  # Windows/Linux simple bind connection username:password
  rusthound.exe -d domain.local -u user@domain.local -p Password123 -o output -z
  # Linux with username:password and ADCS module for @ly4k BloodHound version
  rusthound -d domain.local -u 'user@domain.local' -p 'Password123' -o /tmp/adcs --adcs -z
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
* [BloodHound Custom Queries from Exegol - @ShutdownRepo](https://raw.githubusercontent.com/ShutdownRepo/Exegol/master/sources/bloodhound/customqueries.json)
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
  :heavy_exclamation_mark: **Priv Esc to Domain Admin with User Hunting:** \
  I have local admin access on a machine -> A Domain Admin has a session on that machine -> I steal his token and impersonate him ->   
  Profit!

  [PowerView 3.0 Tricks](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)

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