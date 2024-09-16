# AWS - Service - S3 Buckets

An AWS S3 bucket is a cloud-based storage container that holds files, known as objects, which can be accessed over the internet. It is highly scalable and can store large amounts of data, such as documents, images, and backups. S3 provides robust security through access control, encryption, and permissions management. It ensures high durability and availability, making it ideal for storing and retrieving data from anywhere.

## Tools

* [aws/aws-cli](https://github.com/aws/aws-cli) - Universal Command Line Interface for Amazon Web Services
	```ps1
	sudo apt install awscli
	```
* [digi.ninja/bucket-finder](https://digi.ninja/projects/bucket_finder.php) - Search for public buckets, list and download all files if directory indexing is enabled
	```powershell
	wget https://digi.ninja/files/bucket_finder_1.1.tar.bz2 -O bucket_finder_1.1.tar.bz2
	./bucket_finder.rb my_words
	./bucket_finder.rb --region ie my_words
	./bucket_finder.rb --download --region ie my_words
	./bucket_finder.rb --log-file bucket.out my_words
	```
* [aws-sdk/boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) - Amazon Web Services (AWS) SDK for Python
	```python
	import boto3
	s3 = boto3.client('s3',aws_access_key_id='AKIAJQDP3RKREDACTED',aws_secret_access_key='igH8yFmmpMbnkcUaCqXJIRIozKVaREDACTED',region_name='us-west-1')

	try:
		result = s3.list_buckets()
		print(result)
	except Exception as e:
		print(e)
	```
* [nccgroup/s3_objects_check](https://github.com/nccgroup/s3_objects_check) - Whitebox evaluation of effective S3 object permissions, to identify publicly accessible files
    ```powershell
    $ python3 -m venv env && source env/bin/activate
    $ pip install -r requirements.txt
    $ python s3-objects-check.py -h
    $ python s3-objects-check.py -p whitebox-profile -e blackbox-profile
    ```
* [grayhatwarfare/buckets](https://buckets.grayhatwarfare.com/) - Search Public Buckets


## Credentials and Profiles

Create a profile with your `AWSAccessKeyId` and `AWSSecretKey`, then you can use `--profile nameofprofile` in the `aws` command.

```js
aws configure --profile nameofprofile
AWS Access Key ID [None]: <AWSAccessKeyId>
AWS Secret Access Key [None]: <AWSSecretKey>
Default region name [None]: 
Default output format [None]: 
```

Alternatively you can use environment variables instead of creating a profile.

```bash
export AWS_ACCESS_KEY_ID=ASIAZ[...]PODP56
export AWS_SECRET_ACCESS_KEY=fPk/Gya[...]4/j5bSuhDQ
export AWS_SESSION_TOKEN=FQoGZXIvYXdzE[...]8aOK4QU=
```


## Open S3 Bucket

An open S3 bucket refers to an Amazon Simple Storage Service (Amazon S3) bucket that has been configured to allow public access, either intentionally or by mistake. This means that anyone on the internet could potentially access, read, or even modify the data stored in the bucket, depending on the permissions set.

* [http://s3.amazonaws.com/<bucket-name>/](http://s3.amazonaws.com/<bucket-name>/)
* [http://<bucket-name>.s3.amazonaws.com/](http://<bucket-name>.s3.amazonaws.com/)

AWS S3 buckets name examples: [http://flaws.cloud.s3.amazonaws.com](http://flaws.cloud.s3.amazonaws.com). 

Either bruteforce the buckets name with keyword related to your target or search through the leaked one using OSINT tool such as [buckets.grayhatwarfare.com](https://buckets.grayhatwarfare.com/).

When file listing is enabled, the name is also displayed inside the `<Name>` XML tag.

```xml
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
<Name>adobe-REDACTED-REDACTED-REDACTED</Name>
```


## Bucket Interations

### Find the Region

To find the region of an Amazon Web Services (AWS) service (such as an S3 bucket) using dig or nslookup, query the DNS records for the service's domain or endpoint.

```bash
$ dig flaws.cloud
;; ANSWER SECTION:
flaws.cloud.    5    IN    A    52.218.192.11

$ nslookup 52.218.192.11
Non-authoritative answer:
11.192.218.52.in-addr.arpa name = s3-website-us-west-2.amazonaws.com.
```


### List Files

To list files in an AWS S3 bucket using the AWS CLI, you can use the following command:

```bash
aws s3 ls <target> [--options]
aws s3 ls s3://bucket-name --no-sign-request --region <insert-region-here>
aws s3 ls s3://flaws.cloud/ --no-sign-request --region us-west-2
```


### Copy, Upload and Download Files

* Copy
	```bash
	aws s3 cp <source> <target> [--options]
	aws s3 cp local.txt s3://bucket-name/remote.txt --acl authenticated-read
	aws s3 cp login.html s3://bucket-name --grants read=uri=http://acs.amazonaws.com/groups/global/AllUsers
	```

* Upload
	```bash
	aws s3 mv <source> <target> [--options]
	aws s3 mv test.txt s3://hackerone.files
	SUCCESS : "move: ./test.txt to s3://hackerone.files/test.txt"
	```

* Download
	```bash
	aws s3 sync <source> <target> [--options]
	aws s3 sync s3://level3-9afd3927f195e10225021a578e6f78df.flaws.cloud/ . --no-sign-request --region us-west-2
	```


## References

* [There's a Hole in 1,951 Amazon S3 Buckets - Mar 27, 2013 - Rapid7 willis](https://community.rapid7.com/community/infosec/blog/2013/03/27/1951-open-s3-buckets)
* [Bug Bounty Survey - AWS Basic test](https://web.archive.org/web/20180808181450/https://twitter.com/bugbsurveys/status/860102244171227136)
* [flaws.cloud Challenge based on AWS vulnerabilities - Scott Piper - Summit Route](http://flaws.cloud/)
* [flaws2.cloud Challenge based on AWS vulnerabilities - Scott Piper - Summit Route](http://flaws2.cloud)
* [Guardzilla video camera hardcoded AWS credential - INIT_6 - December 27, 2018](https://blackmarble.sh/guardzilla-video-camera-hard-coded-aws-credentials/)
* [AWS PENETRATION TESTING PART 1. S3 BUCKETS - VirtueSecurity](https://www.virtuesecurity.com/aws-penetration-testing-part-1-s3-buckets/)
* [AWS PENETRATION TESTING PART 2. S3, IAM, EC2 - VirtueSecurity](https://www.virtuesecurity.com/aws-penetration-testing-part-2-s3-iam-ec2/)
* [A Technical Analysis of the Capital One Hack - CloudSploit - Aug 2 2019](https://blog.cloudsploit.com/a-technical-analysis-of-the-capital-one-hack-a9b43d7c8aea?gi=8bb65b77c2cf)