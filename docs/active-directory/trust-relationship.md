# Trust - Relationship

* One-way
  * Domain B trusts A
  * Users in Domain A can access resources in Domain B
  * Users in Domain B cannot access resources in Domain A
* Two-way
  * Domain A trusts Domain B
  * Domain B trusts Domain A
  * Authentication requests can be passed between the two domains in both directions


## Enumerate trusts between domains

* Native `nltest`
  ```powershell
  nltest /trusted_domains
  ```
* PowerShell `GetAllTrustRelationships`
  ```powershell
  ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()

  SourceName          TargetName                    TrustType      TrustDirection
  ----------          ----------                    ---------      --------------
  domainA.local      domainB.local                  TreeRoot       Bidirectional
  ```
* Crackmapexec module `enum_trusts`
  ```powershell
  cme ldap <ip> -u <user> -p <pass> -M enum_trusts 
  ```


## Exploit trusts between domains

:warning: Require a Domain-Admin level access to the current domain.

| Source     | Target  | Technique to use  | Trust relationship  |
|---|---|---|---|
| Root      | Child  | Golden Ticket + Enterprise Admin group (Mimikatz /groups) | Inter Realm (2-way)  |
| Child     | Child  | SID History exploitation (Mimikatz /sids)                 | Inter Realm Parent-Child (2-way)  |
| Child     | Root   | SID History exploitation (Mimikatz /sids)                 | Inter Realm Tree-Root (2-way)  |
| Forest A  | Forest B  | PrinterBug + Unconstrained delegation ?  | Inter Realm Forest or External (2-way)  |