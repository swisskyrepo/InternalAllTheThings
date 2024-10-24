# AWS - CLI

The AWS Command Line Interface (CLI) is a unified tool to manage AWS services from the command line. Using the AWS CLI, you can control multiple AWS services, automate tasks, and manage configurations through profiles.


## Set up AWS CLI

Install AWS CLI and configure it for the first time:

```ps1
aws configure
```

This will prompt for:

* AWS Access Key ID
* AWS Secret Access Key
* Default region name
* Default output format


## Creating Profiles

You can configure multiple profiles in `~/.aws/credentials` and `~/.aws/config`.

* `~/.aws/credentials` (stores credentials)

    ```ini
    [default]
    aws_access_key_id = <default-access-key>
    aws_secret_access_key = <default-secret-key>

    [dev-profile]
    aws_access_key_id = <dev-access-key>
    aws_secret_access_key = <dev-secret-key>

    [prod-profile]
    aws_access_key_id = <prod-access-key>
    aws_secret_access_key = <prod-secret-key>
    ``` 

* `~/.aws/config` (stores region and output settings)

    ```ini
    [default]
    region = us-east-1
    output = json

    [profile dev-profile]
    region = us-west-2
    output = yaml

    [profile prod-profile]
    region = eu-west-1
    output = json
    ``` 

You can also create profiles via the command line:

```ps1
aws configure --profile dev-profile
```



## Using Profiles

When running AWS CLI commands, you can specify which profile to use by adding the `--profile` flag:

```ps1
aws s3 ls --profile dev-profile
```

If no profile is specified, the **default** profile is used.