# Azure Services - Application Endpoint

## Enumerate

* Enumerate possible endpoints for applications starting/ending with PREFIX
    ```powershell
    PS C:\Tools> Get-AzureADServicePrincipal -All $true -Filter "startswith(displayName,'PREFIX')" | % {$_.ReplyUrls}
    PS C:\Tools> Get-AzureADApplication -All $true -Filter "endswith(displayName,'PREFIX')" | Select-Object ReplyUrls,WwwHomePage,HomePage
    ```


## Access

```ps1
https://myapps.microsoft.com/signin/<App ID>?tenantId=<TenantID>
```


## References

* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)