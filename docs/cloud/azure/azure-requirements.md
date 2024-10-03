# Azure - Requirements

## Pentest Requirements

Users and roles:

* **Global Reader** and **Security Reader** roles in Azure AD
* **Reader** permission over the subscription

Subscriptions:

* [Azure Dev/Test](https://azure.microsoft.com/en-us/pricing/offers/dev-test) subscription.
* Visual Studio subscription determines the monthly Azure credits you receive
    * Visual Studio Enterprise: $150/month
    * MSDN Platforms: $100
    * Visual Studio Professional: $50
    * Visual Studio Test Professional: $50

## Powershell and Native Modules

* [Microsoft Graph](https://learn.microsoft.com/en-us/powershell/microsoftgraph/installation?view=graph-powershell-1.0): `Install-Module Microsoft.Graph -Scope CurrentUser`
* [Azure AD](https://learn.microsoft.com/fr-fr/powershell/azure/active-directory/install-adv2?view=azureadps-2.0): `Install-Module AzureAD`
* [Azure AD Preview](https://learn.microsoft.com/fr-fr/powershell/azure/active-directory/install-adv2?view=azureadps-2.0): `Install-Module AzureADPreview`
* [Azure CLI](https://learn.microsoft.com/fr-fr/cli/azure/install-azure-cli-windows?tabs=winget): `winget install -e --id Microsoft.AzureCLI`


## Terminology

* **Tenant**: An instance of Azure AD and represents a single organization.
* **Azure AD Directory**: Each tenant has a dedicated Directory. This is used to perform identity and access management functions for resources.
* **Subscriptions**: It is used to pay for services. There can be multiple subscriptions in a Directory.
* **Core Domain**: The initial domain name <tenant>.onmicrosoft.com is the core domain. It is possible to define custom domain names too.


## References

* [Az - Permissions for a Pentest - HackTricks](https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-permissions-for-a-pentest)
* [An introduction to penetration testing Azure - HollyGraceful - 06 August 2021](https://akimbocore.com/article/introduction-to-pentesting-azure/)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)