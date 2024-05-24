# Azure Services - Deployment Template

* List the deployments
    ```powershell
    PS Az> Get-AzResourceGroup
    PS Az> Get-AzResourceGroupDeployment -ResourceGroupName SAP
    ```
* Export the deployment template
    ```ps1
    PS Az> Save-AzResourceGroupDeploymentTemplate -ResourceGroupName <RESOURCE GROUP> -DeploymentName <DEPLOYMENT NAME>
    
    # search for hardcoded password
    cat <DEPLOYMENT NAME>.json 
    cat <PATH TO .json FILE> | Select-String password
    ```


## References

* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)