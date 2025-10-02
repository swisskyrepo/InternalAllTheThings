# Active Directory - Certificate ESC5

## ESC5 - Vulnerable PKI Object Access Control

> Escalate the privileges from **Domain Administrator** in the child domain into **Enterprise Administrator** at the forest root.

**Requirements**:

* Add new templates to the "Certificate" Templates container
* "WRITE" access to the `pKIEnrollmentService` object

**Exploitation**:

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

## References

* [From DA to EA with ESC5 - Andy Robbins - May 16, 2023](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c)
