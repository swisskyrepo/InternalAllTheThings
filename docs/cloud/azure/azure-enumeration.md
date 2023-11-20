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
    roadrecon gather
    ```
* AzureHound
    ```ps1
    ./azurehound -r REFRESH_TOKEN list --tenant domain.local -o output.json
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
| Device requirement        | / |
| MFA                       | / |
| Legacy Protocols          | / |
| Compliant Device (Intune) | / |
| Domain Joined             | / |


## Azure AD - MFA

* [dafthack/MFASweep](https://github.com/dafthack/MFASweep) - A tool for checking if MFA is enabled on multiple Microsoft Services
```ps1
Import-Module .\MFASweep.ps1
Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020
Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020 -Recon -IncludeADFS
```

