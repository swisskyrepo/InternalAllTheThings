# AWS - Service - Cognito

* [Cognito Scanner](https://github.com/padok-team/cognito-scanner) - A CLI tool for executing attacks on cognito such as *Unwanted account creation*, *Account Oracle* and *Identity Pool escalation*.

    ```ps1
    # Installation
    $ pip install cognito-scanner
    # Usage
    $ cognito-scanner --help
    # Get information about how to use the unwanted account creation script
    $ cognito-scanner account-creation --help
    # For more details go to https://github.com/padok-team/cognito-scanner
    ```

## Get User Information

```ps1
aws cognito-idp get-user --access-token $(cat access_token.txt)
```

## Admin Authentication

```ps1
aws cognito-idp admin-initiate-auth --access-token $(cat access_token)
```

## List User Groups

```ps1
aws cognito-idp admin-list-groups-for-user --username user.name@email.com --user-pool-id "Group-Name"
```

## Sign up

```ps1
aws cognito-idp sign-up --client-id <client-id> --username <username> --password <password>
```

## Modify Attributes

```ps1
aws cognito-idp update-user-attributes --access-token $(cat access_token) --user-attributes Name=<attribute>,Value=<value>
```

## References

* TODO
