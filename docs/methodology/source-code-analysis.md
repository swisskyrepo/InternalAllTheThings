# Source Code Analysis

> Source code analysis is the process of examining and reviewing the code of a software program to identify errors, vulnerabilities, and potential improvements. This can be performed manually by developers or through automated tools that scan the code for issues like security risks, coding standard violations, and performance inefficiencies.


## Semgrep

**Install**:

* Ubuntu/WSL/Linux/macOS: `python3 -m pip install semgrep`
* macOS: `brew install semgrep`
* Docker:
    ```ps1
    docker run -it -v "${PWD}:/src" semgrep/semgrep semgrep login
    docker run -e SEMGREP_APP_TOKEN=<TOKEN> --rm -v "${PWD}:/src" semgrep/semgrep semgrep ci
    ```

**Semgrep rules**:

* [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) - Official Semgrep rules registry
* [trailofbits/semgrep-rules](https://github.com/trailofbits/semgrep-rules) - Semgrep queries developed by Trail of Bits
* [Decurity/semgrep-smart-contracts)](https://github.com/Decurity/semgrep-smart-contracts) - Semgrep rules for smart contracts based on DeFi exploits
* [0xdea/semgrep-rules](https://github.com/0xdea/semgrep-rules) - A collection of Semgrep rules to facilitate vulnerability research.


## SonarQube

**Install**

* Docker: `docker run -d --name sonarqube -e SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true -p 9000:9000 sonarqube:latest`

**Configuration**

* Go to localhost:9000
* Login with `admin:admin`
* Create a local project 
* Generate a token for the project
* Use `sonar-scanner-cli` with the generated token

    ```ps1
    docker run --rm -e SONAR_HOST_URL="http://10.10.10.10:9000" -v "/tmp/www:/usr/src" sonarsource/sonar-scanner-cli -Dsonar.projectKey=DDI -Dsonar.sources=. -Dsonar.host.url=http://10.10.10.10:9000 -Dsonar.token=sqp_redacted
    ```

:warning: remove dead symbolic links before scanning a folder.


## CodeQL

[TODO](#TODO)


## Snyk

[TODO](#TODO)


## References

* [TODO](#TODO)