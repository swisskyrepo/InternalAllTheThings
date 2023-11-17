# OSINT AAD - Recon Domains

Extract openly available information for the given tenant: https://aadinternals.com/osint/

```ps1
Invoke-AADIntReconAsOutsider -Domain "company.com" | Format-Table
Invoke-AADIntReconAsOutsider -UserName "user@company.com" | Format-Table
```

# Azure AD - Collectors

* roadrecon
    ```ps1
    roadrecon auth --access-token eyJ0eXA...
    roadrecon gather
    ```
* AzureHound
    ```ps1
    ./azurehound -r REFRESH_TOKEN list --tenant domain.local -o output.json
    ```


# Azure AD - Conditionnal Access

Enumerate Conditionnal Access Policies: `roadrecon plugin policies`

# Azure AD - MFA

* [dafthack/MFASweep](https://github.com/dafthack/MFASweep) - A tool for checking if MFA is enabled on multiple Microsoft Services
```ps1
Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020
Invoke-MFASweep -Username targetuser@targetdomain.com -Password Winter2020 -Recon -IncludeADFS
```

