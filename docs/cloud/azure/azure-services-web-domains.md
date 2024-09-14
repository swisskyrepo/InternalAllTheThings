# Azure Services - DNS Suffix

## DNS table 

Many Azure services generate custom endpoints with a suffix such as `.cloudapp.azure.com`, `.windows.net`. Below is a table of common services and their associated DNS suffixes.

These services can also be leveraged for domain fronting or communication with an external C2 server when they are whitelisted by the proxy or the firewall rules.

| Service | Domain |
| --- | --- |
| Analysis Services Suffix | .asazure.windows.net |
| API Management Suffix | .azure-api.net |
| App Services Suffix | .azurewebsites.net |
| Automation Suffix | .azure-automation.net |
| Batch Suffix | .batch.azure.com |
| Blob Endpoint Suffix | .blob.core.windows.net |
| CDN Suffix | .azureedge.net |
| Data Lake Analytics Catalog Suffix | .azuredatalakeanalytics.net |
| Data Lake Store Suffix | .azuredatalakestore.net |
| DocumentDB/CosmosDB Suffix | .documents.azure.com |
| Event Hubs Suffix | .servicesbus.windows.net |
| File Endpoint Suffix | .file.core.windows.net |
| FrontDoor Suffix | .azurefd.net |
| IoT Hub Suffix | .azure-devices.net |
| Key Vault Suffix | .vault.azure.net |
| Logic App Suffix | .azurewebsites.net |
| Queue Endpoint Suffix | .queue.core.windows.net |
| Redis Cache Suffix | .redis.cache.windows.net |
| Service Bus Suffix | .servicesbus.windows.net	 |
| Service Fabric Suffix | .cloudapp.azure.com |
| SQL Database Suffix | .database.windows.net |
| Storage Endpoint Suffix | .core.windows.net |
| Table Endpoint Suffix | .table.core.windows.net |
| Traffic Manager Suffix | .trafficmanager.net |
| Web Application Gateway Suffix | .cloudapp.azure.com |


## References

* [Azure services URLs and IP addresses for firewall or proxy whitelisting - Daniel Neumann - 20. December 2016](https://www.danielstechblog.io/azure-services-urls-and-ip-addresses-for-firewall-or-proxy-whitelisting/)