# INC-002 — SSH Brute-Force Detection and Investigation

**Project:** Enterprise SOC Threat Detection and Incident Response
**Incident ID:** INC-002  
**Detection ID:** SOC-DET-001  
**Incident Date:** November 8, 2026 (Ubuntu server log time)  
**Status:** Closed — Authorized Security Simulation  
**Detection Severity:** Level 8 (Wazuh)  
**Classification:** True Positive Detection — Authorized Testing  
**MITRE ATT&CK:** T1110 — Brute Force

---

## 1. Executive Summary

On November 8, 2026, the Security Operations Center (SOC) detected repeated Secure Shell (SSH) authentication failures targeting a monitored Linux server, `LINUX-SVR-01`.

The activity was identified by a custom Wazuh correlation rule, `100100`, developed to detect repeated SSH authentication failures originating from the same source IP address within a defined time window.

Investigation revealed six failed password authentication attempts against the `vboxuser` account, originating from `192.168.56.10` and targeting `192.168.56.20`.

The activity was confirmed to be part of an authorized security simulation conducted from an SSH session on the SOC server.

No successful SSH authentication was observed in the reviewed incident window, and no evidence of unauthorized access was identified in the collected authentication logs.

The incident was classified as a **True Positive Detection — Authorized Security Testing** and closed without containment actions.

## 2. Business Context and Security Objective

In an enterprise environment, SSH is commonly used by system administrators to manage Linux servers remotely.

Repeated authentication failures can indicate password guessing, credential misuse, or attempted unauthorized access.

If such activity goes undetected, an attacker may eventually obtain valid credentials and compromise critical systems.

The purpose of this exercise was to:

- Develop and deploy a custom detection rule for repeated SSH authentication failures.
- Correlate authentication events originating from the same IP address.
- Validate the detection against live endpoint activity.
- Investigate the security alert using centralized and endpoint logs.
- Determine whether unauthorized access occurred.
- Document the investigation using a structured SOC incident response process.

## 3. Lab Environment

| Component | Configuration | Function |
|---|---|---|
| Windows Host | Windows with PowerShell | Remote administration |
| Virtualization | Oracle VirtualBox | Virtual lab infrastructure |
| SOC-SIEM-01 | Ubuntu Server, 192.168.56.10 | Wazuh SIEM and test origin |
| LINUX-SVR-01 | Ubuntu Server, 192.168.56.20 | Monitored Linux endpoint |
| Wazuh Manager | Wazuh 4.x | Event analysis and correlation |
| Wazuh Agent | Wazuh 4.14.10 | Endpoint log collection |
| Log Source | systemd-journald | SSH authentication events |
| Protocol | SSH / TCP 22 | Remote authentication |

### Network Flow

Windows PowerShell → SSH → SOC-SIEM-01 (192.168.56.10)

SOC-SIEM-01 → SSH authentication tests → LINUX-SVR-01 (192.168.56.20)

LINUX-SVR-01 → Wazuh Agent → SOC-SIEM-01 → Wazuh Dashboard

The authentication events recorded the SOC server's IP address because the test commands were executed within the remote SSH session on `SOC-SIEM-01`.

## 4. Detection Engineering

### 4.1 Detection Objective

Develop an early-warning correlation rule capable of detecting repeated SSH authentication failures from the same source IP address.

### 4.2 Custom Wazuh Rule

**Rule ID:** 100100  
**Detection Name:** SOC-DET-001 — Repeated SSH Authentication Failures  
**Severity:** Level 8  
**Frequency:** 5 matching events  
**Timeframe:** 120 seconds  
**Correlation:** Same source IP address

```xml
<rule id="100100" level="8" frequency="5" timeframe="120">
  <if_matched_sid>5760</if_matched_sid>
  <same_source_ip />
  <description>SOC-DET-001: Repeated SSH authentication failures from the same source IP</description>
  <group>authentication_failures,ssh_password_guessing,</group>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

The custom rule correlates events previously matched by Wazuh Rule `5760`, which identifies individual SSH authentication failures.

The rule was created in:

`/var/ossec/etc/rules/local_rules.xml`

### 4.3 Existing Wazuh Detection

Wazuh also provides built-in Rule `5763`, which detects repeated SSH authentication failures.

The custom rule uses a lower threshold to provide an earlier warning of suspicious authentication patterns.

| Detection | Rule ID | Frequency | Timeframe | Severity |
|---|---|---|---|---|
| Individual SSH failure | 5760 | Single event | N/A | 5 |
| Custom early-warning detection | 100100 | 5 | 120 seconds | 8 |
| Built-in brute-force detection | 5763 | 8 | 120 seconds | 10 |

The custom threshold was selected for lab validation. Production deployment would require baseline analysis, false-positive evaluation, and tuning.

## 5. Detection Validation

### 5.1 Wazuh Logtest Validation

The custom rule was initially tested using the Wazuh Logtest utility.

A synthetic SSH authentication failure event was submitted repeatedly using a consistent source IP address.

The test confirmed:

- Successful syslog pre-decoding.
- Successful SSH event decoding.
- Identification of source IP and target username.
- Matching of the base authentication failure rule.
- Successful triggering of custom correlation Rule `100100`.

**Result:** Passed.

### 5.2 Live Detection Validation

Six controlled SSH authentication failures were generated against `LINUX-SVR-01`.

The authentication attempts originated from `SOC-SIEM-01` and targeted the `vboxuser` account.

Wazuh successfully generated a live alert with the following attributes:

| Field | Observed Value |
|---|---|
| Rule ID | 100100 |
| Rule Level | 8 |
| Rule Frequency | 5 |
| Agent | LINUX-SVR-01 |
| Agent ID | 001 |
| Agent IP | 192.168.56.20 |
| Source IP | 192.168.56.10 |
| Destination User | vboxuser |
| Source Port (triggering event) | 49746 |
| MITRE ATT&CK | T1110 — Brute Force |
| Alert Description | SOC-DET-001: Repeated SSH authentication failures from the same source IP |

**Result:** Passed — custom detection successfully generated a live Wazuh alert.

## 6. Incident Timeline

*Times below are taken from the Linux server authentication logs on November 8, 2026.*

| Time | Event | Observation |
|---|---|---|
| 06:59:07 | PAM authentication failure | Initial authentication failure recorded |
| 06:59:09 | SSH authentication failure | First failed password |
| 06:59:16 | SSH authentication failure | Second failed password |
| 06:59:22 | SSH authentication failure | Third failed password |
| 06:59:23 | SSH connection closed | First connection terminated during pre-authentication |
| 07:00:21 | SSH authentication failure | Fourth failed password |
| 07:00:26 | SSH authentication failure | Fifth failed password; custom alert generated |
| 07:00:32 | SSH authentication failure | Sixth failed password |
| 07:00:33 | SSH connection closed | Second connection terminated during pre-authentication |

The six failed password attempts occurred over approximately 83 seconds, within the custom rule's configured 120-second correlation window.

## 7. Security Investigation

### 7.1 Initial Alert Triage

The SOC investigation began by reviewing the custom alert in Wazuh Threat Hunting.

The alert identified repeated SSH authentication failures associated with:

- Source IP: `192.168.56.10`
- Target endpoint: `LINUX-SVR-01`
- Target username: `vboxuser`
- Detection Rule: `100100`
- Alert severity: Level 8

### 7.2 Source Attribution

The source IP was identified as the SOC SIEM server.

Further examination of the testing workflow confirmed that the authentication attempts were intentionally performed from within an SSH session on `SOC-SIEM-01`, accessed through Windows PowerShell.

The activity was therefore attributed to authorized lab testing.

### 7.3 Authentication Log Analysis

Endpoint authentication logs were reviewed using:

```bash
sudo journalctl -u ssh --since "2026-11-08 06:55:00" --until "2026-11-08 07:10:00" --no-pager
```

The investigation confirmed:

- Six failed SSH password attempts.
- Two SSH connection groups.
- A single source IP address.
- One targeted user account.
- Authentication failures recorded by SSH and PAM.
- Both connections closed during pre-authentication.

### 7.4 Successful Authentication Review

The incident-window logs were examined for successful SSH authentication and session activity.

No successful SSH authentication was observed in the supplied log output for the reviewed period.

The investigation therefore found no evidence of a successful login associated with the simulated password-guessing activity.

This finding is limited to the reviewed authentication evidence and does not represent a comprehensive host compromise assessment.

## 8. MITRE ATT&CK Mapping

**Tactic:** Credential Access  
**Technique:** T1110 — Brute Force

Repeated SSH password attempts can represent attempts to discover or guess valid account credentials.

The custom Wazuh detection was mapped to T1110 because it identifies multiple failed authentication events from the same source IP address within a short time window.

The detection does not independently establish attacker intent or successful credential compromise.

## 9. Incident Response and Disposition

### 9.1 Containment Assessment

No containment actions were required because the activity was confirmed as authorized security testing.

The investigation did not identify a successful SSH login associated with the simulated authentication attempts.

### 9.2 Final Incident Classification

**Detection Outcome:** True Positive  
**Activity Classification:** Authorized Security Simulation  
**Confirmed Unauthorized Access:** None identified  
**Containment:** Not required  
**Incident Status:** Closed

### 9.3 Response Recommendations

In a production enterprise environment, an equivalent alert would warrant:

1. Verification of the source IP and asset ownership.
2. Investigation of related successful authentication events.
3. Review of the targeted account's privileges.
4. Correlation with endpoint and network security telemetry.
5. Assessment of whether the activity is authorized.
6. Escalation or containment if malicious activity is confirmed.
7. Consideration of SSH hardening, key-based authentication, MFA where supported, and source access restrictions.

## 10. Evidence Collected

The following evidence supports the detection and investigation.

### Evidence 1 — Linux SSH Authentication Logs

![Live SSH Authentication Failures](../evidence/INC-002/01-live-ssh-failures.png)

Shows failed SSH password attempts recorded by the Linux endpoint.

### Evidence 2 — Custom Wazuh Detection

![Custom Wazuh Rule 100100 Alert](../evidence/INC-002/02-custom-rule-alert.png)

Shows the live custom detection alert in Wazuh Threat Hunting.

### Evidence 3 — Alert Document Details

![Wazuh Alert Details](../evidence/INC-002/03-alert-details.png)

Shows the source IP, target account, affected endpoint, and original authentication event.

### Evidence 4 — MITRE ATT&CK Mapping

![MITRE ATT&CK Mapping](../evidence/INC-002/04-mitre-attack-mapping.png)

Shows the custom rule severity, correlation frequency, and MITRE ATT&CK classification.

**Evidence Directory:** [INC-002 Evidence](../evidence/INC-002/)

## 11. Lessons Learned

### Detection Engineering

Custom correlation rules can improve early detection of repeated authentication failures before higher-threshold built-in alerts are generated.

### Log Parsing and Normalization

Consistent syslog formatting is essential for reliable parsing. During testing, a zero-padded day in the syslog timestamp allowed Wazuh Logtest to recognize the SSH event correctly.

### Source Attribution

An SSH session established from Windows does not mean commands executed within the remote Linux shell originate from Windows. The source IP reflects the system initiating the subsequent connection.

### Alert Investigation

A detection alert should initiate investigation rather than automatically establish compromise. Analysts must validate source attribution, authentication outcomes, and business context.

### Evidence-Based Documentation

Recording rule configurations, raw events, alert details, timestamps, and final disposition makes investigations reproducible and auditable.

## 12. Conclusion

INC-002 demonstrated successful development, validation, and deployment of a custom Wazuh SSH authentication correlation rule in an enterprise-style SOC lab.

The detection identified repeated authentication failures from a single source IP and generated a Level 8 alert.

Subsequent investigation confirmed that the activity was an authorized simulation and found no successful SSH authentication in the reviewed incident-window logs.

The exercise demonstrated practical skills in SIEM monitoring, detection engineering, security event correlation, threat investigation, MITRE ATT&CK mapping, and incident documentation.

**Final Disposition: Closed — True Positive Detection / Authorized Security Simulation.**
