# Web Attack Surface

## Summary

* [Enumerate Subdomains](#enumerate-subdomains)
    * [Subdomains Databases](#subdomains-databases)
    * [Bruteforce Subdomains](#bruteforce-subdomains)
    * [Certificate Transparency Logs](#certificate-transparency-logs)
    * [DNS Resolution](#dns-resolution)
    * [Technology Discovery](#technology-discovery)
* [Subdomain Takeover](#subdomain-takover)
* [References](#references)

## Enumerate Subdomains

Subdomain enumeration is the process of identifying all subdomains associated with a main domain (e.g., finding `blog.example.com`, `shop.example.com`, etc., for `example.com`).

### Subdomains Databases

Many databases and tools aggregate data from a variety of online sources, such as DNS databases, certificate transparency logs, APIs (e.g., Shodan, VirusTotal), and other publicly available sources to compile a comprehensive list of potential subdomains.

* [projectdiscovery/chaos-client](https://github.com/projectdiscovery/chaos-client) - Go client to communicate with Chaos DB API.

  ```ps1
  chaos -d hackerone.com
  ```

* [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) - Fast passive subdomain enumeration tool.

  ```ps1
  subfinder -d hackerone.com
  ```

* [owasp-amass/amass](https://github.com/owasp-amass/amass) - In-depth attack surface mapping and asset discovery

  ```ps1
  amass enum -d example.com
  ```

* [Findomain/Findomain](https://github.com/Findomain/Findomain) - The complete solution for domain recognition.

  ```ps1
  findomain -t example.com -u /tmp/example.com.out
  ```

### Bruteforce Subdomains

Subdomain brute-forcing is a technique used to discover subdomains of a target domain by systematically trying out potential subdomain names against it. This is done by using a predefined list of common or likely subdomain names, known as a wordlist. Each word in the wordlist is appended to the target domain (e.g., admin.example.com, mail.example.com) to check if it resolves to a valid subdomain.

* [assetnote/wordlists](https://github.com/assetnote/wordlists)
* [danielmiessler/SecLists/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)
* [jhaddix/all.txt](https://gist.github.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a)

Unlike passive subdomain enumeration, which relies on existing data from sources, brute-forcing actively queries DNS records to discover live subdomains that may not be listed in public databases.

* [infosec-au/altdns](https://github.com/infosec-au/altdns) - Generates permutations, alterations and mutations of subdomains and then resolves them.

  ```powershell
  altdns.py -i /tmp/inputdomains.txt -o /tmp/out.txt -w ./words.txt
  ```

* [owasp-amass/amass](https://github.com/owasp-amass/amass) - In-depth attack surface mapping and asset discovery.

  ```ps1
  amass enum -active -brute -o /tmp/hosts.txt -d $1
  ```

* [projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) - A fast and multi-purpose DNS toolkit allow to run multiple DNS queries of your choice with a list of user-supplied resolvers.

  ```ps1
  dnsx -silent -d facebook.com -w dns_worldlist.txt
  ```

* [subfinder/goaltdns](https://github.com/subfinder/goaltdns) - A permutation generation tool written in golang.

  ```ps1
  altdns -l ./input_domains.txt -o ./output.txt
  ```

### Certificate Transparency Logs

Certificate Transparency (CT) logs are public databases that record all SSL/TLS certificates issued by certificate authorities (CAs). These logs are designed to improve the security and transparency of the SSL/TLS ecosystem by making it easier to monitor and audit certificates.

* [CertStream Calidog](https://certstream.calidog.io/)
* [Meta Certificate Transparency](https://developers.facebook.com/docs/certificate-transparency)
* [Google Certificate Transparency](certificate.transparency.dev)

### DNS Resolution

Once you've generated a list of potential subdomains, the next step is to resolve them to retrieve their DNS records (A and AAAA) to obtain their IPv4 and IPv6 addresses.

* [blechschmidt/massdns](https://github.com/blechschmidt/massdns)

  ```ps1
  cat /tmp/results_subfinder.txt | massdns -r ./resolvers.txt -t A -o S -w /tmp/results_subfinder_resolved.txt
  ```

* [projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) - a fast and multi-purpose DNS toolkit allow to run multiple DNS queries of your choice with a list of user-supplied resolvers.

  ```ps1
  subfinder -silent -d hackerone.com | dnsx -silent -a -resp
  subfinder -silent -d hackerone.com | dnsx -silent -cname -resp
  subfinder -silent -d hackerone.com | dnsx -silent  -asn
  echo 173.0.84.0/24 | dnsx -silent -resp-only -ptr
  echo AS17012 | dnsx -silent -resp-only -ptr 
  ```

## Technology Discovery

Technology discovery is the process of identifying the underlying technologies, software, and frameworks used by a website or digital infrastructure. This often includes detecting web servers, CMS platforms, programming languages, databases, JavaScript libraries, and other software components.

* [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) - A fast and multi-purpose HTTP toolkit that allows running multiple probes using the retryablehttp library.

  ```ps1
  httpx -u 'https://example.com' -title -tech-detect -status-code -follow-redirects
  ```

* [projectdiscovery/wappalyzergo](https://github.com/projectdiscovery/wappalyzergo) - A high performance go implementation of Wappalyzer Technology Detection Library.
* [michenriksen/aquatone](https://github.com/michenriksen/aquatone) - A Tool for Domain Flyovers

  ```ps1
  cat hosts.txt | aquatone -ports 80,443,3000,3001
  ```

* [rverton/webanalyze](https://github.com/rverton/webanalyze) - Port of Wappalyzer in Go

  ```ps1
  webanalyze -host example.com -crawl 1
  ```

* [wappalyzer](https://www.wappalyzer.com/) - Identify technologies on websites.

## Subdomain Takover

A subdomain takeover is a type of security vulnerability that occurs when a subdomain (e.g., `sub.example.com`) is still live but its DNS records point to a service or platform (like AWS S3, GitHub Pages, or Heroku) that is no longer active or properly configured. This situation can allow an attacker to claim the unclaimed resource and take control of the subdomain, enabling them to host malicious content or impersonate the legitimate website.

For example, if `sub.example.com` points to an AWS S3 bucket that has been deleted or abandoned, an attacker could create a new S3 bucket with the same name, gaining control over the subdomain and potentially causing security risks, like phishing attacks or reputational damage to the main domain.

Refer to [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) for a list of services and guidance on claiming subdomains with dangling DNS records.

* [projectdiscovery/nuclei-templates/http/takeovers](https://github.com/projectdiscovery/nuclei-templates/tree/main/http/takeovers) - Community curated list of templates for the nuclei engine to find security vulnerabilities.

    ```powershell
    nuclei -t nuclei-templates/http/takeovers -u https://example.com
    ```

* [anshumanbh/tko-subs](https://github.com/anshumanbh/tko-subs) - A tool that can help detect and takeover subdomains with dead DNS records

    ```powershell
    ./bin/tko-subs -domains=./lists/domains_tkos.txt -data=./lists/providers-data.csv  
    ```

## References

* [Subdomain Takeover: Proof Creation for Bug Bounties - Patrik Hudak (@0xpatrik) - May 21, 2018](https://0xpatrik.com/takeover-proofs/)
* [Subdomain Takeover: Basics - Patrik Hudak (@0xpatrik) - June 27, 2018](https://0xpatrik.com/subdomain-takeover-basics/)
