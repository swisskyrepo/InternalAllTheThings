# Endpoint Detection and Response

Endpoint Detection and Response (EDR) is a security solution that combines real-time monitoring, data collection, and advanced analytics to detect, investigate, and respond to cyber threats at the endpoint level. Leveraging machine learning algorithms and behavioral analysis, EDR tools can identify malicious activities, automate containment and remediation actions, and provide forensic insights to enhance an organization's overall security posture.


## Static Detection

**Mechanism**: Static detection is a security technique used in EDR and antivirus software that analyzes files and applications without executing them, typically based on predefined signatures or known malicious patterns. 

**Bypass**:

- Obfuscate strings
- Dynamically resolving strings
- Dynamically resolving imports, reducing the `Import Address Table` (IAT)
- Custom `GetProcAddress` and `GetModuleHandle`
- API Hashing


## User Behavioural Analysis

**Mechanism**: User Behavioral Analysis (UBA) monitors and analyzes user activities and patterns to detect anomalies and potential threats. 

**Bypass**:

- Learning about OPSEC methods


## Usermode Windows Function Monitoring

**Mechanism**: Usermode Windows Function Monitoring is a technique that tracks and analyzes the execution of Windows API (Application Programming Interface) calls and functions within user space processes.

**Bypass**:

- Unhooking
- Indirect syscalls


## Call Stack Analysis

**Mechanism**: Checking the origin of function calls via the Call Stack chain

**Bypass**:

- TODO
- TODO


## Process Analysis

**Mechanism**: Process analysis includes inspecting memory regions, identifying remote process access, and assessing child processes to gain insights into process relationships, uncover hidden or suspicious activities.

**Bypass**:

- Avoid RWX memory region (RW->RX)
- Break parent-child link (e.g: word.exe spawning cmd.exe)
- TODO


## Kernel Callbacks

**Mechanism**: Kernel callbacks in the context of Endpoint Detection and Response (EDR) are functions registered by kernel drivers that get triggered in response to specific events or actions within the operating system's kernel. 

**Bypass**:

- TODO


## References

* [Flying Under the Radar: Part 1: Resolving Sensitive Windows Functions with x64 Assembly - theepicpowner - Apr 24, 2024](https://theepicpowner.gitlab.io/posts/Flying-Under-the-Radar-Part-1/)
* [Malware AV/VM evasion - part 16: WinAPI GetProcAddress implementation. Simple C++ example - cocomelonc](https://cocomelonc.github.io/malware/2023/04/16/malware-av-evasion-16.html)
* [Custom GetProcAddress And GetModuleHandle Implementation (X64) - daax - December 15, 2016](https://revers.engineering/custom-getprocaddress-and-getmodulehandle-implementation-x64/)