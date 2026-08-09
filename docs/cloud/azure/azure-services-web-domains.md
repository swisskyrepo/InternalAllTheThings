# Azure Services - DNS Suffix

## DNS Tables

Many Azure services dynamically generate custom endpoints utilizing a trusted cloud suffix (such as `.cloudapp.azure.com` or `.windows.net`). Maintaining a structured inventory of these suffixes is critical for security auditing, zero-trust network design, and defensive threat research.

These services can also be leveraged for domain fronting, subdomain takeover, or communication with an external C2 server when they are whitelisted by proxy or firewall rules.

---

## DNS Tables by Category

### Compute & Containers

| Service                                                  | Domain                                  |
| -------------------------------------------------------- | --------------------------------------- |
| App Services (Web App / API App / Function App) Suffix   | `.azurewebsites.net`                    |
| App Service SCM / Kudu (Deployment Suffix)               | `.scm.azurewebsites.net`                |
| Azure Static Web Apps Suffix                             | `.azurestaticapps.net`                  |
| Azure Container Apps Environment Suffix                  | `.<UID>.<REGION>.azurecontainerapps.io` |
| Azure Container Registry Suffix                          | `.azurecr.io`                           |
| Azure Kubernetes Service (AKS) API Suffix                | `.azmk8s.io`                            |
| Azure Container Instance (ACI) Suffix                    | `.azurecontainer.io`                    |
| Azure Container Instance (ACI) Internal Suffix           | `.internal.azurecontainer.io`           |
| Azure Spring Apps Suffix                                 | `.azuremicroservices.io`                |
| Batch Suffix                                             | `.batch.azure.com`                      |
| Cloud Services (Classic) & VMs Suffix                    | `.cloudapp.net`                         |
| Cloud Services (Extended Support) & Resource Manager VMs | `.cloudapp.azure.com`                   |
| Service Fabric Suffix                                    | `.cloudapp.azure.com`                   |

### DevOps & Developer Tooling

| Service                    | Domain           |
| -------------------------- | ---------------- |
| Azure DevOps Modern Suffix | `.dev.azure.com` |

### Management, Hybrid & Observability

| Service                                        | Domain                           |
| ---------------------------------------------- | -------------------------------- |
| Azure Management Services (ARM) Suffix         | `.management.core.windows.net`   |
| Azure Arc Hybrid Suffix                        | `.azurearc.microsoft.com`        |
| Azure Bastion Suffix                           | `.bastion.azure.com`             |
| Azure Virtual Desktop (WVD) Suffix             | `.wvd.microsoft.com`             |
| Log Analytics Data Ingestion (ODS) Suffix      | `.ods.opinsights.azure.com`      |
| Log Analytics Agent Communication (OMS) Suffix | `.oms.opinsights.azure.com`      |
| Azure Monitor Suffix                           | `.monitor.azure.com`             |
| Azure Automation Agent Service Suffix          | `.agentsvc.azure-automation.net` |
| Automation Suffix                              | `.azure-automation.net`          |
| App Configuration Suffix                       | `.azconfig.io`                   |
| Microsoft Purview Suffix                       | `.purview.azure.com`             |

### Backup & Disaster Recovery

| Service                    | Domain                                    |
| -------------------------- | ----------------------------------------- |
| Azure Backup Suffix        | `.backup.windowsazure.com`                |
| Azure Site Recovery Suffix | `.hypervrecoverymanager.windowsazure.com` |

### Storage & Data Lakes

| Service                                  | Domain                        |
| ---------------------------------------- | ----------------------------- |
| Blob Endpoint Suffix                     | `.blob.core.windows.net`      |
| File Endpoint Suffix                     | `.file.core.windows.net`      |
| Queue Endpoint Suffix                    | `.queue.core.windows.net`     |
| Table Endpoint Suffix                    | `.table.core.windows.net`     |
| Data Lake Gen2 (DFS) Suffix              | `.dfs.core.windows.net`       |
| Data Lake Store (Gen 1) Suffix           | `.azuredatalakestore.net`     |
| Data Lake Analytics Catalog Suffix       | `.azuredatalakeanalytics.net` |
| Static Web Sites (Storage-hosted) Suffix | `.web.core.windows.net`       |

### Databases & Analytics

| Service                                        | Domain                         |
| ---------------------------------------------- | ------------------------------ |
| SQL Database Suffix                            | `.database.windows.net`        |
| Cosmos DB (SQL/Document API) Suffix            | `.documents.azure.com`         |
| Cosmos DB (NoSQL API) Suffix                   | `.cosmos.azure.com`            |
| Cosmos DB (Cassandra API) Suffix               | `.cassandra.cosmos.azure.com`  |
| Cosmos DB (Gremlin API) Suffix                 | `.gremlin.cosmos.azure.com`    |
| Cosmos DB (MongoDB API) Suffix                 | `.mongo.cosmos.azure.com`      |
| Cosmos DB (Table API) Suffix                   | `.table.cosmos.azure.com`      |
| Azure Database for PostgreSQL Suffix           | `.postgres.database.azure.com` |
| Azure Database for MySQL Suffix                | `.mysql.database.azure.com`    |
| Azure Database for MariaDB Suffix              | `.mariadb.database.azure.com`  |
| Azure Synapse Analytics (SQL) Suffix           | `.sql.azuresynapse.net`        |
| Azure Synapse Analytics (Dev/Workspace) Suffix | `.dev.azuresynapse.net`        |
| Azure Databricks Suffix                        | `.azuredatabricks.net`         |
| Azure HDInsight Suffix                         | `.azurehdinsight.net`          |
| Redis Cache Suffix                             | `.redis.cache.windows.net`     |
| Analysis Services Suffix                       | `.asazure.windows.net`         |

### Networking & Content Delivery

| Service                              | Domain                    |
| ------------------------------------ | ------------------------- |
| Traffic Manager Suffix               | `.trafficmanager.net`     |
| Front Door (Classic) Suffix          | `.azurefd.net`            |
| Front Door (Standard/Premium) Suffix | `.<hash>.z01.azurefd.net` |
| CDN Suffix                           | `.azureedge.net`          |
| CDN Edge / Origin Suffix             | `.vo.msecnd.net`          |

### AI, Machine Learning & Cognitive Services

| Service                                       | Domain                         |
| --------------------------------------------- | ------------------------------ |
| Azure AI Services (Cognitive Services) Suffix | `.cognitiveservices.azure.com` |
| Azure OpenAI Suffix                           | `.openai.azure.com`            |
| Azure AI Search Suffix                        | `.search.windows.net`          |
| Azure Machine Learning API Suffix             | `.api.azureml.ms`              |
| Azure Machine Learning Notebook Suffix        | `.notebooks.azure.net`         |

### Integration & IoT

| Service                                          | Domain                            |
| ------------------------------------------------ | --------------------------------- |
| API Management Suffix                            | `.azure-api.net`                  |
| Service Bus Suffix                               | `.servicebus.windows.net`         |
| Event Hubs Suffix                                | `.servicebus.windows.net`         |
| Event Grid (Topic) Suffix                        | `.eventgrid.azure.net`            |
| Azure Data Factory Suffix                        | `.datafactory.azure.net`          |
| Logic App Suffix                                 | `.azurewebsites.net`              |
| IoT Hub Suffix                                   | `.azure-devices.net`              |
| IoT Hub Device Provisioning Service (DPS) Suffix | `.azure-devices-provisioning.net` |
| Azure IoT Central Suffix                         | `.azureiotcentral.com`            |
| Azure Digital Twins Suffix                       | `.digitaltwins.azure.net`         |
| Azure SignalR Service Suffix                     | `.service.signalr.net`            |

### Identity & Security

| Service                                 | Domain                  |
| --------------------------------------- | ----------------------- |
| Key Vault Suffix                        | `.vault.azure.net`      |
| Managed HSM Suffix                      | `.managedhsm.azure.net` |
| Microsoft Entra ID Suffix (onmicrosoft) | `.onmicrosoft.com`      |
| Microsoft Graph API Suffix              | `.graph.microsoft.com`  |

---

### Sovereign & Cloud Variations

| Cloud Environment      | Domain                                                                               |
| ---------------------- | ------------------------------------------------------------------------------------ |
| Azure US Government    | `.usgovcloudapi.net`, `.database.usgovcloudapi.net`, `.servicebus.usgovcloudapi.net` |
| Azure China (21Vianet) | `.chinacloudapi.cn`, `.core.chinacloudapi.cn`, `.database.chinacloudapi.cn`          |
| Azure Germany (Legacy) | `.cloudapp.de`                                                                       |

---

## References

* [Azure services URLs and IP addresses for firewall or proxy whitelisting - Daniel Neumann - 20. December 2016](https://www.danielstechblog.io/azure-services-urls-and-ip-addresses-for-firewall-or-proxy-whitelisting/)
* [Reference list of Azure domains - Microsoft - 14. May 2024](https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-domains)
* [Azure Storage account overview (Endpoints) - Microsoft - 14. February 2024](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview#storage-account-endpoints)
* [Compare Azure Government and global Azure - Microsoft - 28. February 2024](https://learn.microsoft.com/en-us/azure/azure-government/compare-azure-government-global-azure)
* [Developer guide for Azure China 21Vianet - Microsoft - 15. January 2024](https://learn.microsoft.com/en-us/azure/china/resources-developer-guide)
