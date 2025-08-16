# Source Code Analysis

> Source code analysis is the process of examining and reviewing the code of a software program to identify errors, vulnerabilities, and potential improvements. This can be performed manually by developers or through automated tools that scan the code for issues like security risks, coding standard violations, and performance inefficiencies.

## Semgrep

> Lightweight static analysis for many languages. Find bug variants with patterns that look like source code.

**Install**:

* Binaries: [opengrep/opengrep](https://github.com/opengrep/opengrep) / [semgrep/semgrep](https://github.com/semgrep/semgrep)
* Ubuntu/WSL/Linux/macOS: `python3 -m pip install semgrep`
* macOS: `brew install semgrep`
* Docker

    ```ps1
    docker run -it -v "${PWD}:/src" semgrep/semgrep semgrep login
    docker run -e SEMGREP_APP_TOKEN=<TOKEN> --rm -v "${PWD}:/src" semgrep/semgrep semgrep ci
    ```

**Semgrep rules**:

* [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules) - Official Semgrep rules registry
* [trailofbits/semgrep-rules](https://github.com/trailofbits/semgrep-rules) - Semgrep queries developed by Trail of Bits
* [Decurity/semgrep-smart-contracts)](https://github.com/Decurity/semgrep-smart-contracts) - Semgrep rules for smart contracts based on DeFi exploits
* [0xdea/semgrep-rules](https://github.com/0xdea/semgrep-rules) - A collection of Semgrep rules to facilitate vulnerability research.

**Other Tools**:

* [Orange-Cyberdefense/grepmarx](https://github.com/Orange-Cyberdefense/grepmarx) - A source code static analysis platform for AppSec enthusiasts, based on semgrep engine.

## SonarQube

> Continuous Inspection

**Install**

* Docker

    ```ps1
    docker run -d --name sonarqube -p 9000:9000 sonarqube:community
    ```

**Configuration**

* Go to localhost:9000
* Login with `admin:admin`
* Create a local project
* Generate a token for the project
* Use `sonar-scanner-cli` with the generated token

    ```ps1
    docker run --rm -e SONAR_HOST_URL="http://10.10.10.10:9000" -v "/tmp/www:/usr/src" sonarsource/sonar-scanner-cli -Dsonar.projectKey=sonar-project-name -Dsonar.sources=. -Dsonar.host.url=http://10.10.10.10:9000 -Dsonar.token=sqp_redacted
    ```

* Check the Security Hotspots tab: `http://10.10.10.10:9000/security_hotspots?id=sonar-project-name`

:warning: remove dead symbolic links before scanning a folder.

## Psalm

> A static analysis tool for finding errors in PHP applications

**Install**

```ps1
composer require --dev vimeo/psalm
```

**Configuration**

* Create a project and initiate a scan of the codebase

    ```ps1
    ./vendor/bin/psalm --init
    ./vendor/bin/psalm --taint-analysis
    ./vendor/bin/psalm --report=results.sarif
    ```

* Use a Sarif viewer to see the results: [microsoft.github.io/sarif-web-component](https://microsoft.github.io/sarif-web-component/)

## CodeQL

> CodeQL: the libraries and queries that power security researchers around the world, as well as code scanning in GitHub Advanced Security

**Install**:

* [github/codeql](https://github.com/github/codeql)

**Configuration**

```ps1
codeql resolve packs
codeql resolve languages
codeql database create <database> --language=<language-identifier>
codeql database create --language=python <output-folder>/python-database
codeql database create --language=cpp <output-folder>/cpp-database
codeql database analyze <database> --format=<format> --output=<output> <query-specifiers>...
codeql database analyze /codeql-dbs/example-repo javascript-code-scanning.qls --sarif-category=javascript-typescript  --format=sarif-latest --output=/temp/example-repo-js.sarif
codeql database analyze <database> microsoft/coding-standards@1.0.0 github/security-queries --format=sarifv2.1.0 --output=query-results.sarif --download
```

## Snyk

> Snyk CLI scans and monitors your projects for security vulnerabilities.

**Install**

* [Snyk Security - Visual Studio](https://marketplace.visualstudio.com/items?itemName=snyk-security.snyk-vulnerability-scanner-vs)
* [Snyk Code / Snyk Open Source](https://app.snyk.io)

    ```ps1
    curl https://static.snyk.io/cli/latest/snyk-linux -o snyk
    chmod +x ./snyk
    mv ./snyk /usr/local/bin/ 

    docker run -it \
        -e "SNYK_TOKEN=<TOKEN>" \
        -v "<PROJECT_DIRECTORY>:/project" \
        -v "/home/user/.gradle:/home/node/.gradle" \
    snyk/snyk:gradle:6.4 test --org=my-org-name
    ```

**Configuration**

```ps1
snyk auth
snyk ignore --file-path=<directory_or_file>
snyk code test

# npm install snyk-to-html -g
snyk code test --json | snyk-to-html -o results-opensource.html
```

## References

* [Code auditing 101 - Rodolphe Ghio - August 2, 2025](https://blog.rodolpheg.xyz/posts/code-auditing--101/)
* [Detect PHP security vulnerabilities with Psalm - Matt Brown - June 23, 2020](https://psalm.dev/articles/detect-security-vulnerabilities-with-psalm)
* [Security Analysis in Psalm - Official Documentation](https://psalm.dev/docs/security_analysis/)
