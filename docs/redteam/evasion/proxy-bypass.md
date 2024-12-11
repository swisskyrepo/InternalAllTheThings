# Proxy Bypass

> An HTTP proxy server acts as an intermediary between a client (like a web browser) and a web server. It processes client requests for web resources, fetches them from the destination server, and returns them to the client.

## Summary

* [Methodology](#methodology)
    * [Discover Proxy Configuration](#discover-proxy-configuration)
    * [PAC Proxy](#pac-proxy)
    * [Common Bypass](#common-bypass)
* [References](#references)

## Methodology

### Discover Proxy Configuration

* Windows, in the registry key `DefaultConnectionSettings`

    ```ps1
    Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\DefaultConnectionSettings
    Software\Microsoft\Windows\CurrentVersion\Internet Settings\ProxyServer
    ```

* Windows:

    ```ps1
    netsh winhttp show proxy
    ```

* Linux, in the environment variables `http_proxy` and `https_proxy`

    ```ps1
    env
    cat /etc/profile.d/proxy.conf
    ```

### PAC Proxy

PAC (Proxy Auto-Configuration) is a method to automatically determine whether web traffic should go through a proxy server. It uses a .pac file that contains a JavaScript function called `FindProxyForURL(url, host)`.

* proxy.pac
* wpad.dat

**Example**:

```ps1
function FindProxyForURL(url, host) {
    if (dnsDomainIs(host, '.example.com')) {
        return 'DIRECT';
    }
    return 'PROXY proxy.example.com:8080';
}
```

**Tools**:

* [PortSwigger - Proxy Auto Config](https://portswigger.net/bappstore/7b3eae07aa724196ab85a8b64cd095d1) - This extension automatically configures Burp upstream proxies to match desktop proxy settings. This includes support for Proxy Auto-Config (PAC) scripts.

### Common Bypass

* Try several way to reach the Internet
    * IP address
    * Domain categorized in Health/Finance

* Use another proxy reachable in the same environment

* Weak regular expression for URL can be abused to bypass the proxy configuration

    ```ps1
    user:pass@domain/endpoint?parameter#hash
    e.g: microsoft.com:microsoft.com@microsoft.com.evil.com/microsoft.com?microsoft.com#microsoft.com
    ```

* Trusted Websites: [Living Off Trusted Sites (LOTS) Project](https://lots-project.com/)
    * Amazon Cloud: AWS endpoints
    * Microsoft Cloud: Azure endpoints
    * Google Cloud: GCP endpoints
    * live.sysinternals.com

* User-Agents
    * Tools related User-Agent: curl, python, powershell

        ```ps1
        User-Agent: curl/8.11.0
        User-Agent: python-requests/2.32.3
        User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; fr-FR) WindowsPowerShell/5.1.26100.2161
        ```

    * Platform related User-Agent: Android/iOS/Tablet

        ```ps1
        Mozilla/5.0 (Linux; Android 14; Pixel 9 Build/AD1A.240905.004; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/129.0.6668.78 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/484.0.0.63.83;IABMV/1;] 
        Mozilla/5.0 (iPhone; CPU iPhone OS 18_0_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 [FBAN/FBIOS;FBAV/485.1.0.45.110;FBBV/665337277;FBDV/iPhone17,1;FBMD/iPhone;FBSN/iOS;FBSV/18.0.1;FBSS/3;FBCR/;FBID/phone;FBLC/it_IT;FBOP/80] 
        ```

* Domain Fronting
* Protocols
    * TCP
    * Websocket (HTTP)
    * DNS Exfiltration

## References

* [Proxy managed by enterprise? No problem! Abusing PAC and the registry to get burpin’ - Thomas Grimée - August 17, 2021](https://blog.nviso.eu/2021/08/17/proxy-managed-by-enterprise-no-problem-abusing-pac-and-the-registry-to-get-burpin/)
* [Proxy: Internal Proxy - MITRE ATT&CK - March 14, 2020](https://attack.mitre.org/versions/v16/techniques/T1090/001/)
