# enterprise-soc-threat-detection-
Enterprise SOC simulation using Wazuh SIEM, Linux endpoint monitoring, threat detection, MITRE ATT&amp;CK mapping, and incident response investigations.
# Enterprise SOC Threat Detection & Incident Response Lab

## Project Overview

This project simulates Security Operations Center (SOC) activities in a small enterprise environment using Wazuh SIEM, Ubuntu Linux, and Oracle VirtualBox.

The goal is to demonstrate practical SOC analyst skills, including security monitoring, log analysis, threat detection, alert triage, MITRE ATT&CK mapping, and incident investigation.

The lab is designed around realistic business security scenarios and uses controlled simulations to generate and investigate security events.

## Architecture

| Component | Technology | Purpose |
|---|---|---|
| Host system | Windows | Virtualization host and analyst workstation |
| Virtualization | Oracle VirtualBox | Hosts the enterprise SOC environment |
| SOC-SIEM-01 | Ubuntu Server, Wazuh 4.14 | Centralized security monitoring and analysis |
| LINUX-SVR-01 | Ubuntu Linux, Wazuh Agent 4.14.10 | Monitored enterprise endpoint |
| SIEM network | 192.168.56.0/24 | Host-only lab communication |

**Network configuration:**
- SOC-SIEM-01: `192.168.56.10`
- LINUX-SVR-01: `192.168.56.20`
- NAT interfaces provide outbound internet connectivity.

## SOC Capabilities

- Centralized log collection and analysis
- Linux endpoint security monitoring
- SSH authentication monitoring
- Security alert investigation and triage
- MITRE ATT&CK technique mapping
- Investigation documentation and evidence collection

## Security Investigation Scenarios

| Case ID | Scenario | Status |
|---|---|---|
| INC-001 | SSH Authentication Failure Investigation | Detection verified; documentation in progress |
| INC-002 | SSH Brute-Force Detection and Correlation | Planned |
| INC-003 | Linux Privilege Escalation Investigation | Planned |
| INC-004 | File Integrity Monitoring | Planned |
| INC-005 | Suspicious Network Activity | Planned |

## INC-001: SSH Authentication Failure

**Objective:** Detect and investigate failed SSH authentication attempts against a monitored Linux server.

**Test environment:** Authorized, isolated VirtualBox lab.

### Observed Results

- Wazuh successfully received authentication events from the Linux endpoint through journald.
- Failed SSH password attempts generated Wazuh security alerts.
- Wazuh Rule ID: `5760`
- Wazuh Rule Level: `5`
- Detection Description: `sshd: authentication failed.`
- Target Account: `vboxuser`

### MITRE ATT&CK Mapping

- **T1110.001:** Brute Force — Password Guessing
- **T1021.004:** Remote Services — SSH

### Analyst Assessment

The alert was a true-positive detection of an intentionally generated authentication failure.

The observed activity was part of an authorized security simulation. No unauthorized access or system compromise was established.

## Skills Demonstrated

- SIEM installation and administration
- Linux system administration
- Network configuration and troubleshooting
- Wazuh agent deployment
- Security event collection
- SSH authentication log analysis
- Alert investigation and classification
- MITRE ATT&CK mapping
- Technical documentation

## Project Roadmap

**Phase 1 — SOC Infrastructure and Initial Detection**

Wazuh deployment, endpoint onboarding, SSH monitoring, and initial alert verification.

**Phase 2 — Detection Engineering**

Custom detection rules, correlation, and alert validation.

**Phase 3 — Threat Investigation**

Privilege escalation, file integrity monitoring, and suspicious activity investigations.

**Phase 4 — Incident Response and Reporting**

Incident documentation, containment exercises, and SOC operational reporting.

## Disclaimer

All activities are conducted in an authorized, isolated laboratory environment for educational and defensive security purposes. No production systems or third-party assets are targeted.
