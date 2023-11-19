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

### Register Devices


# Service Principals