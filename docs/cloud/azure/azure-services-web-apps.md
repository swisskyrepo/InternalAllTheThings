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


## Kudu

In Azure App Service, Kudu is the advanced management and deployment tool used for various operations such as continuous integration, troubleshooting, and diagnostic tasks for your web applications. It provides a set of utilities and features for managing your app’s environment, including access to application settings, log streams, and deployment management. 

You can access this Kudu app at the following URLs:

* App not in the Isolated tier: `https://<app-name>.scm.azurewebsites.net`
* Internet-facing app in the Isolated tier (App Service Environment): `https://<app-name>.scm.<ase-name>.p.azurewebsites.net`
* Internal app in the Isolated tier (App Service Environment for internal load balancing): `https://<app-name>.scm.<ase-name>.appserviceenvironment.net`

Key Features of Kudu in App Service:

* **Web-Based Console**: Provides a command-line interface (CLI) to execute commands directly on the App Service environment.
* **File Explorer**: Lets you view and manage files in your app’s environment.
* **Environment Diagnostics**: Offers insights into the environment variables, app settings, and detailed diagnostic logs.
* **Process Explorer**: Allows you to monitor and manage running processes in your app’s environment.
* **Access to Logs**: Easily view, download, and stream logs for debugging and troubleshooting.


## References

* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)