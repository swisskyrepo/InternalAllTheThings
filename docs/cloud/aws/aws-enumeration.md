# AWS - Enumerate

## Collectors

* [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite/wiki) - Multi-Cloud Security Auditing Tool
    ```powershell
    $ python scout.py PROVIDER --help
    # The --session-token is optional and only used for temporary credentials (i.e. role assumption).
    $ python scout.py aws --access-keys --access-key-id <AKIAIOSFODNN7EXAMPLE> --secret-access-key <wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY> --session-token <token>
    $ python scout.py azure --cli
    ```

* [RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu) - Exploit configuration flaws within an AWS environment using an extensible collection of modules with a diverse feature-set
    ```powershell
    $ bash install.sh
    $ python3 pacu.py
    set_keys/swap_keys
    run <module_name> [--keyword-arguments]
    run <module_name> --regions eu-west-1,us-west-1
    ```

* [salesforce/cloudsplaining](https://github.com/salesforce/cloudsplaining) - An AWS IAM Security Assessment tool that identifies violations of least privilege and generates a risk-prioritized report
    ```powershell
    $ pip3 install --user cloudsplaining
    $ cloudsplaining download --profile myawsprofile
    $ cloudsplaining scan --input-file default.json
    ```

* [duo-labs/cloudmapper](https://github.com/duo-labs/cloudmapper) - CloudMapper helps you analyze your Amazon Web Services (AWS) environments
    ```powershell
    sudo apt-get install autoconf automake libtool python3.7-dev python3-tk jq awscli build-essential
    pipenv install --skip-lock
    pipenv shell
    report: Generate HTML report. Includes summary of the accounts and audit findings.
    iam_report: Generate HTML report for the IAM information of an account.
    audit: Check for potential misconfigurations.
    collect: Collect metadata about an account.
    find_admins: Look at IAM policies to identify admin users and roles, or principals with specific privileges
    ```

* [cyberark/SkyArk](https://github.com/cyberark/SkyArk) - Discover the most privileged users in the scanned AWS environment, including the AWS Shadow Admins
    ```powershell
    $ powershell -ExecutionPolicy Bypass -NoProfile
    PS C> Import-Module .\SkyArk.ps1 -force
    PS C> Start-AWStealth
    PS C> Scan-AWShadowAdmins  
    ```

* [BishopFox/CloudFox](https://github.com/BishopFox/CloudFox/) - Automating situational awareness for cloud penetration tests. Designed for white box enumeration (SecurityAudit/ReadOnly type permission), but can be used for black box (found credentials) as well.
    ```ps1
    cloudfox aws --profile [profile-name] all-checks
    ```

* [toniblyx/Prowler](https://github.com/toniblyx/prowler) - AWS security best practices assessments, audits, incident response, continuous monitoring, hardening and forensics readiness. It follows guidelines of the CIS Amazon Web Services Foundations Benchmark and DOZENS of additional checks including GDPR and HIPAA (+100).    
    ```powershell
    $ pip install awscli ansi2html detect-secrets
    $ sudo apt install jq
    $ ./prowler -E check42,check43
    $ ./prowler -p custom-profile -r us-east-1 -c check11
    $ ./prowler -A 123456789012 -R ProwlerRole
    ```

* [nccgroup/PMapper](https://github.com/nccgroup/PMapper) - A tool for quickly evaluating IAM permissions in AWS
    ```powershell
    pip install principalmapper
    pmapper graph --create
    pmapper visualize --filetype png
    pmapper analysis --output-type text

    # Determine if PowerUser can escalate privileges
    pmapper query "preset privesc user/PowerUser"
    pmapper argquery --principal user/PowerUser --preset privesc

    # Find all principals that can escalate privileges
    pmapper query "preset privesc *"
    pmapper argquery --principal '*' --preset privesc

    # Find all principals that PowerUser can access
    pmapper query "preset connected user/PowerUser *"
    pmapper argquery --principal user/PowerUser --resource '*' --preset connected

    # Find all principals that can access PowerUser
    pmapper query "preset connected * user/PowerUser"
    pmapper argquery --principal '*' --resource user/PowerUser --preset connected
    ```


## AWS - Enumerate IAM permissions

Enumerate the permissions associated with AWS credential set with [andresriancho/enumerate-iam](https://github.com/andresriancho/enumerate-iam)

```powershell
git clone git@github.com:andresriancho/enumerate-iam.git
pip install -r requirements.txt
./enumerate-iam.py --access-key AKIA... --secret-key StF0q...
2019-05-10 15:57:58,447 - 21345 - [INFO] Starting permission enumeration for access-key-id "AKIA..."
2019-05-10 15:58:01,532 - 21345 - [INFO] Run for the hills, get_account_authorization_details worked!
2019-05-10 15:58:01,537 - 21345 - [INFO] -- {
    "RoleDetailList": [
        {
            "Tags": [],
            "AssumeRolePolicyDocument": {
                "Version": "2008-10-17",
                "Statement": [
                    {
...
2019-05-10 15:58:26,709 - 21345 - [INFO] -- gamelift.list_builds() worked!
2019-05-10 15:58:26,850 - 21345 - [INFO] -- cloudformation.list_stack_sets() worked!
2019-05-10 15:58:26,982 - 21345 - [INFO] -- directconnect.describe_locations() worked!
2019-05-10 15:58:27,021 - 21345 - [INFO] -- gamelift.describe_matchmaking_rule_sets() worked!
2019-05-10 15:58:27,311 - 21345 - [INFO] -- sqs.list_queues() worked!
```


## References

* [An introduction to penetration testing AWS - Akimbocore - HollyGraceful - 06 August 2021](https://akimbocore.com/article/introduction-to-penetration-testing-aws/)
* [AWS CLI Cheatsheet - apolloclark](https://gist.github.com/apolloclark/b3f60c1f68aa972d324b)
* [AWS - Cheatsheet - @Magnussen](https://www.magnussen.funcmylife.fr/article_35)
* [Pacu Open source AWS Exploitation framework - RhinoSecurityLabs](https://rhinosecuritylabs.com/aws/pacu-open-source-aws-exploitation-framework/)
* [PACU Spencer Gietzen - 30 juil. 2018](https://youtu.be/XfetW1Vqybw?list=PLBID4NiuWSmfdWCmYGDQtlPABFHN7HyD5)
