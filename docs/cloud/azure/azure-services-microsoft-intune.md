# Azure Services - Microsoft Intune

Microsoft Intune is a cloud-based service that provides mobile device management (MDM) and mobile application management (MAM). It allows organizations to control and secure access to corporate data on mobile devices, including smartphones, tablets, and PCs. With Intune, businesses can enforce security policies, manage apps, and ensure that devices comply with organizational requirements, whether they are company-owned or personal (BYOD).

## Intunes Administration

**Requirements**:

* **Global Administrator** or **Intune Administrator** Privilege

    ```powershell
    Get-AzureADGroup -Filter "DisplayName eq 'Intune Administrators'"
    ```

**Walkthrough**

1. Login into <https://endpoint.microsoft.com/#home> or use Pass-The-PRT
2. Go to **Devices** -> **All Devices** to check devices enrolled to Intune
3. Go to **Scripts** and click on **Add** for Windows 10.
4. Add a **Powershell script**
5. Specify **Add all users** and **Add all devices** in the **Assignments** page.

:warning: It will take up to one hour before you script is executed !

## Intune Scripts

**Requirements**:

* App with permission: `DeviceManagementConfiguration.Read.All`
* `Microsoft.Graph.Intune` dependency installed: `Install-Module Microsoft.Graph.Intune`

**Extract Intune scripts**:

The following scripts are deprecated, use `MgGraph` instead of `MsGraph`, and change the appropriate function `InvokeMgGraph` too.

* [okieselbach/Get-DeviceManagementScripts.ps1](https://raw.githubusercontent.com/okieselbach/Intune/master/Get-DeviceManagementScripts.ps1) - Get all or individual Intune PowerShell scripts and save them in specified folder.

    ```ps1
    Get-DeviceManagementScripts -FolderPath C:\temp -FileName myScript.ps1
    ```

* [okieselbach/Get-DeviceHealthScripts.ps1](https://raw.githubusercontent.com/okieselbach/Intune/master/Get-DeviceHealthScripts.ps1) - Get all or individual Intune PowerShell Health scripts (aka Proactive Remediation scripts) and save them in specified folder.

    ```ps1
    Get-DeviceHealthScripts -FolderPath C:\temp\HealthScripts
    ```

* [secureworks/pytune](https://github.com/secureworks/pytune) - Pytune is a post-exploitation tool for enrolling a fake device into Intune with mulitple platform support.

    ```ps1
    python3 pytune.py entra_join -o Windows -d Windows_pytune -u testuser@*******.onmicrosoft.com -p ***********  
    python3 pytune.py enroll_intune -o Windows -d Windows_pytune -c Windows_pytune.pfx -u testuser@*******.onmicrosoft.com -p *********** 
    python3 pytune.py download_apps -d Windows_pytune -m Windows_pytune_mdm.pfx
    ```

## LAPS

Some organization have recreated LAPS for Azure devices using Intune scripts.

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

## References

* [Microsoft Intune - Microsoft Intune support for Windows LAPS](https://learn.microsoft.com/en-us/mem/intune/protect/windows-laps-overview)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)
* [Get back your Intune Proactive Remediation Scripts - Oliver Kieselbach - September 7, 2022](https://oliverkieselbach.com/2022/09/07/get-back-your-intune-proactive-remediation-scripts/)
* [Get back your Intune PowerShell Scripts - Oliver Kieselbach - February 6, 2020](https://oliverkieselbach.com/2020/02/06/get-back-your-intune-powershell-scripts/)
