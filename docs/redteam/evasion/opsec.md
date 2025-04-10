# OPSEC

## Infrastructure

* Use generic name for DNS, avoid company names
* Use wildcard (*) when issuing certificates to avoid leaking internal name
* Disable staging endpoints or restrict the access
* Do not upload your stealthy binaries to VirusTotal or other online scanners
* Guardrails your payload to trigger for a specific user/domain/computer name
* Use a redirector, don't expose your C2 TLS stack to the web

## Behavior

* Avoid calling commands such as `whoami`
    * List your kerberos tickets
    * Look for the owner of the process that spawned your beacon
    * List your environment variables: dir env: and dir env:USERNAME
    * Use a beacon object file (BOF) to bring your own whoami
* DCSync (Replication) is always done between domain controllers
    * DCSync from machine accounts look more legit than with a user account
    * You don’t need to dump the whole database, the account krbtgt will grant you every access you need.

## IOC

**Gophish**:

* Default `RID` parameter: [gophish/campaign.go#L130](https://github.com/gophish/gophish/blob/8e79294413932fa302212d8e785b281fb0f8896d/models/campaign.go#L130)
* Default `X-Mailer` header containing the `ServerName`: [gophish/config.go#L46](https://github.com/gophish/gophish/blob/8e79294413932fa302212d8e785b281fb0f8896d/config/config.go#L46)
* Default `X-Gophish-Contact`: [gophish/email_request.go#L123](https://github.com/gophish/gophish/blob/8e79294413932fa302212d8e785b281fb0f8896d/models/email_request.go#L123)

**Impacket**:

* smbexec.py is using a service to execute commands. In the earliest version, it was named `BTOBTO` but it has now 8 random characters.
* psexec.py is based on a well known service released on January 2012: [kavika13/RemComSvc](https://github.com/kavika13/RemCom)
* wmiexec.py every command will be prefixed with `cmd.exe /Q` /c : [impacket/wmiexec.py#L127](https://github.com/fortra/impacket/blob/master/examples/wmiexec.py#L127)

**NetExec**:

* NetExec uses Impacket library, it shares the same IOC
* Kerberoasting search filter query all accounts: [NetExec/ldap.py#L931](https://github.com/Pennyw0rth/NetExec/blob/5f29e661b7e2f367faf2af7688f777d8b2d1bf6d/nxc/protocols/ldap.py#L931)

    ```py
    (&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer)))
    ```

**AWS**:

* AWS cli is using Boto3 library, it sends a User-Agent containing the operating system version in every requests
    * Kali Linux OS is raising an alert: [PenTest:IAMUser/KaliLinux](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#pentest-iam-kalilinux)

## References

* [DLS 2024 - RedTeam Fails - "Oops my bad I ruined the operation" - Swissky - January 15, 2024](https://swisskyrepo.github.io/Drink-Love-Share-Rump/)
* [Five Ways I got Caught before Lunch - Mystikcon 2021 - cyberv1s3r1on3 - November 24, 2021](https://youtu.be/qIbrozlf2wM)
