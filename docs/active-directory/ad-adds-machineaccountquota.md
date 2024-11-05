# Active Directory - Machine Account Quota

In Active Directory (AD), the `MachineAccountQuota` is a limit set on how many computer accounts a specific user or group can create in the domain. 

When a user attempts to create a new computer account, AD checks the current number of computer accounts that the user has already created against the defined quota for that user or group. 

However, Active Directory does not store the current count of created machine accounts directly in a user attribute. Instead, you would need to perform a query to count the machine accounts that were created by a specific user.


## Machine Account Quota Process

1. **Quota Definition**: The `MachineAccountQuota` is defined at the domain level and can be set for individual users or groups. By default, it is set to **10** for the "Domain Admins" group and to 0 for standard users, limiting their capability to create computer accounts.

    ```powershell
    nxc ldap <ip> -u user -p pass -M maq
    ```

2. **Creation Process**: When a user attempts to create a new computer account (for example, by using the "Add Computer" option in Active Directory Users and Computers or via PowerShell), the account creation request is made to the domain controllers (DCs).

    ```powershell
    impacket@linux> addcomputer.py -computer-name 'ControlledComputer$' -computer-pass 'ComputerPassword' -dc-host DC01 -domain-netbios domain 'domain.local/user1:complexpassword'
    ```

3. **Quota Evaluation**: Before the account is created, Active Directory checks the current count of computer accounts created by that user. This is done by querying the `msDS-CreatorSID` attribute, which holds the SID of the user who created that object. 
The system compares this count to the `MachineAccountQuota` value set for that user. If the count is less than the quota, the creation proceeds; if it equals or exceeds the quota, the creation is denied, and an error is returned.

    ```powershell
    # Replace DOMAIN\username with the actual domain and user name
    $user = "DOMAIN\username"

    # Get the user's SID
    $userSID = (Get-ADUser -Identity $user).SID

    # Count the number of computer accounts created by this user
    $computerCount = (Get-ADComputer -Filter { msDS-CreatorSID -eq $userSID }).Count

    # Display the count
    $computerCount
    ```

4. **Failure Handling**:
    - If the quota is exceeded, the user attempting to create the account will receive an error message indicating that they cannot create a new computer account because they have reached their quota limit.


## References

* [MachineAccountQuota - The Hacker Recipes - 24/10/2024](https://www.thehacker.recipes/ad/movement/builtins/machineaccountquota)
* [MachineAccountQuota is USEFUL Sometimes: Exploiting One of Active Directory's Oddest Settings - Kevin Robertson - March 6, 2019](https://www.netspi.com/blog/technical-blog/network-penetration-testing/machineaccountquota-is-useful-sometimes/)
* [Machine Account Quota - NetExec - 13/09/2023](https://www.netexec.wiki/ldap-protocol/machine-account-quota)