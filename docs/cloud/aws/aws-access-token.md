# AWS - Access Token & Secrets

## URL Services

| Service      | URL                   |
|--------------|-----------------------|
| s3           | https://{user_provided}.s3.amazonaws.com |
| cloudfront   | https://{random_id}.cloudfront.net |
| ec2          | ec2-{ip-seperated}.compute-1.amazonaws.com |
| es           | https://{user_provided}-{random_id}.{region}.es.amazonaws.com |
| elb          | http://{user_provided}-{random_id}.{region}.elb.amazonaws.com:80/443 |
| elbv2        | https://{user_provided}-{random_id}.{region}.elb.amazonaws.com |
| rds          | mysql://{user_provided}.{random_id}.{region}.rds.amazonaws.com:3306 |
| rds          | postgres://{user_provided}.{random_id}.{region}.rds.amazonaws.com:5432 |
| route 53     | {user_provided} |
| execute-api  | https://{random_id}.execute-api.{region}.amazonaws.com/{user_provided} |
| cloudsearch  | https://doc-{user_provided}-{random_id}.{region}.cloudsearch.amazonaws.com |
| transfer     | sftp://s-{random_id}.server.transfer.{region}.amazonaws.com |
| iot          | mqtt://{random_id}.iot.{region}.amazonaws.com:8883 |
| iot          | https://{random_id}.iot.{region}.amazonaws.com:8443 |
| iot          | https://{random_id}.iot.{region}.amazonaws.com:443 |
| mq           | https://b-{random_id}-{1,2}.mq.{region}.amazonaws.com:8162 |
| mq           | ssl://b-{random_id}-{1,2}.mq.{region}.amazonaws.com:61617 |
| kafka        | b-{1,2,3,4}.{user_provided}.{random_id}.c{1,2}.kafka.{region}.amazonaws.com |
| kafka        | {user_provided}.{random_id}.c{1,2}.kafka.useast-1.amazonaws.com |
| cloud9       | https://{random_id}.vfs.cloud9.{region}.amazonaws.com |
| mediastore   | https://{random_id}.data.mediastore.{region}.amazonaws.com |
| kinesisvideo | https://{random_id}.kinesisvideo.{region}.amazonaws.com |
| mediaconvert | https://{random_id}.mediaconvert.{region}.amazonaws.com |
| mediapackage | https://{random_id}.mediapackage.{region}.amazonaws.com/in/v1/{random_id}/channel |


## Access Key ID & Secret

IAM uses the following prefixes to indicate what type of resource each unique ID applies to. The first four characters are the prefix that depends on the type of the key.

| Prefix       | Resource type           |
|--------------|-------------------------|
| ABIA | AWS STS service bearer token |
| ACCA | Context-specific credential |
| AGPA | User group |
| AIDA | IAM user |
| AIPA | Amazon EC2 instance profile |
| AKIA | Access key |
| ANPA | Managed policy |
| ANVA | Version in a managed policy |
| APKA | Public key |
| AROA | Role |
| ASCA | Certificate |
| ASIA | Temporary (AWS STS) access key |

The rest of the string is Base32 encoded and can be used to recover the account id.

```py
import base64
import binascii

def AWSAccount_from_AWSKeyID(AWSKeyID):
    
    trimmed_AWSKeyID = AWSKeyID[4:] #remove KeyID prefix
    x = base64.b32decode(trimmed_AWSKeyID) #base32 decode
    y = x[0:6]
    
    z = int.from_bytes(y, byteorder='big', signed=False)
    mask = int.from_bytes(binascii.unhexlify(b'7fffffffff80'), byteorder='big', signed=False)
    
    e = (z & mask)>>7
    return (e)


print ("account id:" + "{:012d}".format(AWSAccount_from_AWSKeyID("ASIAQNZGKIQY56JQ7WML")))
```

## Regions

* US Standard - http://s3.amazonaws.com
* Ireland - http://s3-eu-west-1.amazonaws.com
* Northern California - http://s3-us-west-1.amazonaws.com
* Singapore - http://s3-ap-southeast-1.amazonaws.com
* Tokyo - http://s3-ap-northeast-1.amazonaws.com


## Gaining AWS Console Access via API Keys

A utility to convert your AWS CLI credentials into AWS console access.

* Using [NetSPI/aws_consoler](https://github.com/NetSPI/aws_consoler)
    ```powershell
    $> aws_consoler -v -a AKIA[REDACTED] -s [REDACTED]
    2020-03-13 19:44:57,800 [aws_consoler.cli] INFO: Validating arguments...
    2020-03-13 19:44:57,801 [aws_consoler.cli] INFO: Calling logic.
    2020-03-13 19:44:57,820 [aws_consoler.logic] INFO: Boto3 session established.
    2020-03-13 19:44:58,193 [aws_consoler.logic] WARNING: Creds still permanent, creating federated session.
    2020-03-13 19:44:58,698 [aws_consoler.logic] INFO: New federated session established.
    2020-03-13 19:44:59,153 [aws_consoler.logic] INFO: Session valid, attempting to federate as arn:aws:sts::123456789012:federated-user/aws_consoler.
    2020-03-13 19:44:59,668 [aws_consoler.logic] INFO: URL generated!
    https://signin.aws.amazon.com/federation?Action=login&Issuer=consoler.local&Destination=https%3A%2F%2Fconsole.aws.amazon.com%2Fconsole%2Fhome%3Fregion%3Dus-east-1&SigninToken=[REDACTED]
    ```


## References

* [A short note on AWS KEY ID - Tal Be'ery - Oct 27, 2023](https://medium.com/@TalBeerySec/a-short-note-on-aws-key-id-f88cc4317489)
* [Gaining AWS Console Access via API Keys - Ian Williams - March 18th, 2020](https://blog.netspi.com/gaining-aws-console-access-via-api-keys/)