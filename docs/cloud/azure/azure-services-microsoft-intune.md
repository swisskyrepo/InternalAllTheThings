# Azure Services - Microsoft Intune

## LAPS

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


## Intunes Administration

Requirements:
* **Global Administrator** or **Intune Administrator** Privilege : `Get-AzureADGroup -Filter "DisplayName eq 'Intune Administrators'"`

1. Login into https://endpoint.microsoft.com/#home or use Pass-The-PRT
2. Go to **Devices** -> **All Devices** to check devices enrolled to Intune
3. Go to **Scripts** and click on **Add** for Windows 10. 
4. Add a **Powershell script**
5. Specify **Add all users** and **Add all devices** in the **Assignments** page.

:warning: It will take up to one hour before you script is executed !


## References

* [Microsoft Intune - Microsoft Intune support for Windows LAPS](https://learn.microsoft.com/en-us/mem/intune/protect/windows-laps-overview)