# Elastic EDR

> Elastic EDR (Endpoint Detection and Response) is a component of Elastic Security designed to address cybersecurity threats at the endpoint level. It plays a crucial role in preventing, detecting, and responding to cyber threats like ransomware and malware. 

* [peasead/elastic-container](https://github.com/peasead/elastic-container) - Stand up a simple Elastic container with Kibana, Fleet, and the Detection Engine


## Setup

* First, you need `docker` and the `docker-compose` plugin
    ```ps1
    # Add Docker's official GPG key:
    sudo apt-get update
    sudo apt-get install ca-certificates curl
    sudo install -m 0755 -d /etc/apt/keyrings
    sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    sudo chmod a+r /etc/apt/keyrings/docker.asc

    # Add the repository to Apt sources:
    echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
    $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update

    # Install docker from apt
    sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    ```

* You might want to grant the `docker` right to the default user
    ```ps1
    sudo groupadd docker
    sudo usermod -aG docker $USER
    ```

* Install the requirements for the elastic scripts
    ```ps1
    apt-get update
    apt-get install jq git curl
    ```

* Clone the project
    ```ps1
    git clone https://github.com/peasead/elastic-container
    cd elastic-container
    ```

* Edit `.env` to set the credentials and activate rules
    ```ps1
    ELASTIC_PASSWORD="changeme"
    KIBANA_PASSWORD="changeme"
    STACK_VERSION="8.11.2"
    WindowsDR=1
    LICENSE=trial # enable the platinum features
    ```

* Download the images and run the containers
    ```ps1
    chmod +x ./elastic-container.sh
    ./elastic-container.sh start
    ```

* Access the Elastic EDR interface at https://localhost:5601 
* Fleet > `Add agent`
* Enroll in Fleet (recommended)
* Copy Windows PowerShell one-liner and append the `--insecure` flag if you are using untrusted certificates
    ```ps1
    powershell Invoke-WebRequest -Uri https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-7.15.1-windows-x86_64.zip -outfile elastic-agent-7.15.1-windows-x86_64.zip
    Expand-Archive -Path elastic-agent-7.15.1-windows-x86_64.zip -DestinationPath C:\ElasticAgent
    C:\ElasticAgent\elastic-agent-7.15.1-windows-x86_64\elastic-agent.exe install -f --fleet-server-es={{ fleet_server_es }} --fleet-server-service-token={{ fleet_token }} --fleet-server-policy={{ fleet_policy }}
    ```

* Fleet > Integrations > Elastic Defend
    * Switch `Prevent` to `Detect`, to keep the execution running
    * Enable these features to collect more data
        ```
        windows.advanced.memory_protection.shellcode_collect_sample
        windows.advanced.memory_protection.memory_scan_collect_sample
        windows.advanced.memory_protection.shellcode_enhanced_pe_parsing
        ```

* Destroy the containers
    ```ps1
    ./elastic-container.sh destroy
    ```


## References

* [The Elastic Container Project for Security Research - Andrew Pease, Colson Wilhoit, Derek Ditch - 1 March 2023](https://www.elastic.co/security-labs/the-elastic-container-project)
* [Cyber Security Lab Basics - Installing EDR in Malware Development Lab - AhmedS Kasmani](https://www.youtube.com/watch?v=1luhjL7TN9U)
* [Setting Up Elastic 8 with Kibana, Fleet, Endpoint Security, and Windows Log Collection - IppSec - 10 oct. 2022](https://youtu.be/Ts-ofIVRMo4)