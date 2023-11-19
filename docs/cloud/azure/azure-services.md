# Azure Services

## Azure Runbook

Runbook must be SAVED and PUBLISHED before running it.


## Azure Service Principal

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


## Microsoft Intune

* LAPS
    ```ps1
    #requires -modules Microsoft.Graph.Authentication
    #requires -modules Microsoft.Graph.Intune
    #requires -modules LAPS
    #requires -modules ImportExcel

    $DaysBack = 30
    Connect-MgGraph
    Get-IntuneManagedDevice -Filter "Platform eq 'Windows'" |
        Foreach-Object {Get-LapsAADPassword -DevicesIds $_.DisplayName} |
            Where-Object {$_.PasswordExpirationTime -lt (Get-Date).AddDays(-$DaysBack)} |
                Export-Excel -Path "c:\temp\lapsdata.xlsx" - ClearSheet -AutoSize -Show
    ```


## Office 365

### Microsoft Teams Messages

```ps1
TokenTacticsV2> RefreshTo-MSTeamsToken -domain domain.local
AADInternals> Get-AADIntTeamsMessages -AccessToken $MSTeamsToken.access_token | Format-Table id,content,deletiontime,*type*,DisplayName
```


## Outlook Mails

* Read user mails
    ```ps1
    Get-MgUserMessage -UserId <user-id> | ft
    Get-MgUserMessageContent -OutFile mail.txt -UserId <user-id> -MessageId <message-id>
    ```

## OneDrive Files

```ps1
$userId = "<user-id>"
Import-Module Microsoft.Graph.Files
Get-MgUserDefaultDrive -UserId $userId
Get-MgUserDrive -UserId $UserId  -Debug
Get-MgDrive -top 1
```


## References

* [Microsoft Graph - servicePrincipal: addPassword](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-addpassword?view=graph-rest-1.0&tabs=powershell)
* [Microsoft Intune - Microsoft Intune support for Windows LAPS](https://learn.microsoft.com/en-us/mem/intune/protect/windows-laps-overview)