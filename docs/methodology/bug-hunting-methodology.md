# Bug Hunting Methodology

## Passive Recon

* Using [shodan.io](https://www.shodan.io/), [fofa.info](https://en.fofa.info/), [zoomeye.ai](https://www.zoomeye.ai/) or [odin.io](https://search.odin.io/hosts) to detect similar app

  ```ps1
  # https://github.com/glennzw/shodan-hq-nse
  nmap --script shodan-hq.nse --script-args 'apikey=<yourShodanAPIKey>,target=<hackme>'
  ```

* Search for similar websites using the same favicon: [pielco11/fav-up](https://github.com/pielco11/fav-up)

  ```ps1
  python3 favUp.py --favicon-file favicon.ico -sc
  python3 favUp.py --favicon-url https://domain.behind.cloudflare/assets/favicon.ico -sc
  python3 favUp.py --web domain.behind.cloudflare -s
  ```

* Search inside Shortener URLs: [shorteners.grayhatwarfare.com](https://shorteners.grayhatwarfare.com/), [utkusen/urlhunter](https://github.com/utkusen/urlhunter)

  ```ps1
  urlhunter --keywords keywords.txt --date 2020-11-20
  ```

* Search inside Buckets: [buckets.grayhatwarfare.com](https://buckets.grayhatwarfare.com/)

* Using [The Wayback Machine](https://archive.org/web/) to detect forgotten endpoints

  ```powershell
  # Look for JS files, old links
  curl -sX GET "http://web.archive.org/cdx/search/cdx?url=<targetDomain.com>&output=text&fl=original&collapse=urlkey&matchType=prefix"
  ```

* Using [laramies/theHarvester](https://github.com/laramies/theHarvester)

  ```python
  python theHarvester.py -b all -d domain.com
  ```

* Look for private information in [GitHub](https://github.com) repositories with [michenriksen/GitRob](https://github.com/michenriksen/gitrob.git)

  ```bash
  gitrob analyze johndoe --site=https://github.acme.com --endpoint=https://github.acme.com/api/v3 --access-tokens=token1,token2
  ```

* Perform Google Dorks search: [ikuamike/GoogleDorking.md](https://gist.github.com/ikuamike/c2611b171d64b823c1c1956129cbc055)

  ```ps1
  site: *.example.com -www
  intext:"dhcpd.conf" "index of"
  intitle:"SSL Network Extender Login" -checkpoint.com
  ```

* Enumerate subdomains using HackerTarget

  ```ps1
  curl --silent 'https://api.hackertarget.com/hostsearch/?q=targetdomain.com' | grep -o '\w.*targetdomain.com'
  ```

* Enumerate endpoints using CommonCrawl

  ```ps1
  echo "targetdomain.com" | xargs -I domain curl -s "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.targetdomain.com&output=json" | jq -r .url | sort -u
  ```

## Active Recon

### Network Discovery

* Subdomains enumeration
    * Enumerate already found subdomains: [projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder), [OWASP/Amass](https://github.com/OWASP/Amass)

    ```ps1
    subfinder -d hackerone.com
    amass enum -passive -dir /tmp/amass_output/ -d example.com -o dir/example.com
    ```

    * Permutate subdomains: [infosec-au/altdns](https://github.com/infosec-au/altdns)
    * Bruteforce subdomains: [Josue87/gotator](https://github.com/Josue87/gotator)
    * Resolve subdomains to IP with [blechschmidt/massdns](https://github.com/blechschmidt/massdns), remember to use a good list of resolvers like [trickest/resolvers](https://github.com/trickest/resolvers)

    ```ps1
    massdns -r resolvers.txt -o S -w massdns.out subdomains.txt
    ```

    * Subdomain takeovers: [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)

* Network discovery
    * Scan IP ranges with `nmap`, [robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) and [projectdiscovery/naabu](https://github.com/projectdiscovery/naabu)
    * Discover services, version and banners

* Review latest acquisitions

* ASN enumeration
    * [projectdiscovery/asnmap](https://github.com/projectdiscovery/asnmap): `asnmap -a AS45596 -silent`
    * [asnlookup.com](http://www.asnlookup.com)

* DNS Zone Transfer

  ```ps1
  host -t ns domain.local
  domain.local name server master.domain.local.

  host master.domain.local        
  master.domain.local has address 192.168.1.1
 
  dig axfr domain.local @192.168.1.1
  ```

### Web Discovery

#### Common Files

* `security.txt`: A file that provides contact info for reporting security issues with your site (like an email or PGP key).

  ```ps1
  Contact: mailto:security@example.com
  ```

* `sitemap.xml`: Lists all the important URLs of your site so search engines can index them efficiently.

  ```ps1
  <urlset>
    <url><loc>https://example.com/</loc></url>
    <url><loc>https://example.com/about</loc></url>
  </urlset>
  ```

* `robots.txt`: Tells search engine crawlers which pages or files they can or cannot access on your site.

  ```ps1
  User-agent: *
  Disallow: /admin/
  ```

#### Enumerate Files and Folders

List all the subdirectories and files with [OJ/gobuster](https://github.com/OJ/gobuster), [ffuf/ffuf](https://github.com/ffuf/ffuf) and [bitquark/shortscan](https://github.com/bitquark/shortscan)

  ```ps1
  gobuster dir -a 'Mozilla' -e -k -l -t 30 -w mydirfilelist.txt -c 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/'
  ffuf -H 'User-Agent: Mozilla' -v -t 30 -w mydirfilelist.txt -b 'NAME1=VALUE1; NAME2=VALUE2' -u 'https://example.com/FUZZ'
  ```

* Find backup files with [mazen160/bfac](https://github.com/mazen160/bfac)

  ```bash
  bfac --url http://example.com/test.php --level 4
  bfac --list testing_list.txt
  ```

* Crawl through website pages and files: [hakluke/hakrawler](https://github.com/hakluke/hakrawler) and [projectdiscovery/katana](https://github.com/projectdiscovery/katana)

  ```ps1
  katana -u https://tesla.com
  echo https://google.com | hakrawler
  ```

#### Next.js Endpoints

In Next.js, `window.__BUILD_MANIFEST` is a runtime global variable that the framework automatically injects into the client-side JavaScript bundle.

Go to `DevTools->Console` and execute this JavaScript code:

```js
console.log(window.__BUILD_MANIFEST)
console.log(__BUILD_MANIFEST.sortedPages)
```

If you inspect your app in the browser console (for a production build), you might see something like this:

```js
{__rewrites: {…}, /: Array(10), /404: Array(8), /500: Array(4), /_error: Array(1), …}
/: (10) ['static/chunks/2852872c-b605aca0298c2109.js', 'static/chunks/3748-2a8cf394c7270ee0.js']
/404: (8) ['static/chunks/2852872c-b605aca0298c2109.js', 'static/chunks/3748-2a8cf394c7270ee0.js']
/500: (4) ['static/chunks/3748-2a8cf394c7270ee0.js', 'static/chunks/1221-b44c330d41258365.js']
/[slug]: (30) ['static/chunks/2852872c-b605aca0298c2109.js', 'static/chunks/29107295-4cc022cea922dbb4.js']
/_error: ['static/chunks/pages/_error-6ddff449d199572c.js']
/about/[slug]: (31) ['static/chunks/2852872c-b605aca0298c2109.js']
```

#### JS and HTML Comments

Retrieve comments in source code

```html
<!-- HTML Comment -->
// JS Comment
```

#### Internet Archive

Discover URL: [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls), [lc/gau](https://github.com/lc/gau)

  ```ps1
  gau --o example-urls.txt example.com
  gau --blacklist png,jpg,gif example.com
  ```

#### Hidden Parameters

Search for `hidden` parameters: [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner), [s0md3v/Arjun](https://github.com/s0md3v/Arjun) and [Sh1Yo/x8](https://github.com/Sh1Yo/x8)

  ```ps1
  x8 -u "https://example.com/?something=1" -w <wordlist>
  ```

#### Map Technologies

* Web service enumeration using [projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) or [projectdiscovery/wappalyzergo](https://github.com/projectdiscovery/wappalyzergo)
    * Favicon hash
    * JARM fingerprint
    * ASN
    * Status code
    * Services
    * Technologies (Github Pages, Cloudflare, Ruby, Nginx,...)

    ```ps1
    httpx -title -tech-detect -status-code -follow-redirects -jarm -asn -json -silent -ports 80,443 -l urls.txt
    ```

* Look for WAF with [projectdiscovery/cdncheck](https://github.com/projectdiscovery/cdncheck) and identify the real IP with [christophetd/CloudFlair](https://github.com/christophetd/CloudFlair)

  ```ps1
  echo www.hackerone.com | cdncheck -resp
  www.hackerone.com [waf] [cloudflare]
  ```

* Take screenshots for every websites using [sensepost/gowitness](https://github.com/sensepost/gowitness)

#### Manual Testing

Explore the website with a proxy:

* [Caido - A lightweight web security auditing toolkit](https://caido.io/)
* [ZAP - OWASP Zed Attack Proxy](https://www.zaproxy.org/)
* [Burp Suite - Community Edition](https://portswigger.net/burp/communitydownload)

#### Automated vulnerability scanners

* [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei):

  ```ps1
  nuclei -u https://example.com
  ```

* [Burp Suite's web vulnerability scanner](https://portswigger.net/burp/vulnerability-scanner)
* [sullo/nikto](https://github.com/sullo/nikto)

  ```ps1
  ./nikto.pl -h http://www.example.com
  ```

## Looking for Web Vulnerabilities

* Explore the website and look for vulnerabilities listed in this repository: SQL injection, XSS, CRLF, Cookies, ....
* Test for Business Logic weaknesses
    * High or negative numerical values
    * Try all the features and click all the buttons
* [The Web Application Hacker's Handbook Checklist](https://web.archive.org/web/20210126221152/https://gist.github.com/gbedoya/10935137)

* Subscribe to the site and pay for the additional functionality to test

* Inspect Payment functionality - [@gwendallecoguic](https://twitter.com/gwendallecoguic/status/988138794686779392)
  > If the webapp you're testing uses an external payment gateway, check the doc to find the test credit numbers, purchase something and if the webapp didn't disable the test mode, it will be free

  From [https://stripe.com/docs/testing](https://stripe.com/docs/testing#cards) : "Use any of the following test card numbers, a valid expiration date in the future, and any random CVC number, to create a successful payment. Each test card's billing country is set to U.S."

  Test card numbers and tokens  

  | NUMBER           | BRAND          | TOKEN          |
  | :-------------   | :------------- | :------------- |
  | 4242424242424242 | Visa           | tok_visa       |
  | 4000056655665556 | Visa (debit)   | tok_visa_debit |
  | 5555555555554444 | Mastercard     | tok_mastercard |

  International test card numbers and tokens

  | NUMBER           | TOKEN          | COUNTRY        | BRAND          |
  | :-------------   | :------------- | :------------- | :------------- |
  | 4000000400000008 | tok_at         | Austria (AT)   | Visa           |
  | 4000000560000004 | tok_be         | Belgium (BE)   | Visa           |
  | 4000002080000001 | tok_dk         | Denmark (DK)   | Visa           |
  | 4000002460000001 | tok_fi         | Finland (FI)   | Visa           |
  | 4000002500000003 | tok_fr         | France (FR)    | Visa           |

## References

* [[BugBounty] Yahoo phpinfo.php disclosure - Patrik Fehrenbach](https://blog.wss.sh/bugbounty-yahoo-phpinfo-php-disclosure/)
* [Nmap CheatSheet - HackerTarget](https://hackertarget.com/nmap-cheatsheet-a-quick-reference-guide/)
