# Azure Services - Web Apps

## List Web App

```ps1
az webapp list
```

## Execute Commands

```ps1
$ARMToken = Get-ARMTokenWithRefreshToken `
    -RefreshToken "0.ARwA6WgJJ9X2qk..." `
    -TenantID "contoso.onmicrosoft.com"

Invoke-AzureRMWebAppShellCommand `
    -KuduURI "https://<webapp>.scm.azurewebsites.net/api/command" `
    -Token $ARMToken `
    -Command "whoami"
```

## SSH Connection

First check if the SSH over HTTP connection is enabled: `(curl https://${appName}?app.scm.azurewebsites.net/webssh/host).statuscode`


```powershell
az webapp create-remote-connection --subscription <SUBSCRIPTION-ID> --resource-group <RG-NAME> -n <APP-SERVICE-NAME>
```


## References

* []()