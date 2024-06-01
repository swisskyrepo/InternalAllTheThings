# Azure Services - Container Registry

## Enumerate

List container registries in the subscription using Azure CLI 

```ps1
az login -u user@domain.onmicrosoft.com -p pass
az acr list -o table
```

Login to the Registry

```ps1
acr=<ACRName> # from the previous command
server=$(az acr login -n $acr --expose-token --query loginServer -o tsv) 
token=$(az acr login -n $acr --expose-token --query accessToken -o tsv) 
docker login $server -u 00000000-0000-0000-0000-000000000000 -p $token 
```

List the images in the ACR

```ps1
az acr repository list -n $acr 
```

List version tags for an image
```ps1
az acr repository show-tags -n $acr --repository mywebapp
```

Connect to the container registry from a PowerShell console, set the $server and $token variables, and pull the image from the registry

```ps1
# docker login ${registryURI} --username ${username} --password ${password}
$token="<AccessToken>"
$server="<LoginServer>"
docker login $server -u 00000000-0000-0000-0000-000000000000 -p $token
docker pull $server/mywebapp:v1
```

List docker containers inside a registry

```ps1
IEX (New-Object Net.WebClient).downloadstring("https://raw.githubusercontent.com/NetSPI/MicroBurst/master/Misc/Get-AzACR.ps1")
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
Get-AzACR -username ${username} -password ${password} -registry ${registryURI}
```


## References

* [PENTESTING AZURE: RECON TECHNIQUES - April 29, 2022 Stefan Tita](https://securitycafe.ro/2022/04/29/pentesting-azure-recon-techniques/)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)