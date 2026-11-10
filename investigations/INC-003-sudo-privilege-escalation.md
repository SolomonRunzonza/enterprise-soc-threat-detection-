# INC-003 — Repeated Failed Sudo Authentication Investigation

**Project:** Enterprise SOC Threat Detection and Incident Response Lab  
**Incident ID:** INC-003  
**Detection ID:** SOC-DET-002  
**Incident Date:** November 10, 2026 (endpoint log time)  
**Status:** Closed — Authorized Security Simulation  
**Detection Severity:** Level 8 (Wazuh)  
**Classification:** True Positive Detection — Authorized Testing  
**MITRE ATT&CK:** T1548.003 — Sudo and Sudo Caching

---

## 1. Executive Summary

During a controlled security simulation, the Security Operations Center (SOC) detected repeated failed sudo authentication attempts on a monitored Linux server, `LINUX-SVR-01`.

The activity was detected by custom Wazuh correlation Rule `100101`, designed to identify repeated failed sudo authentication events associated with the same user within a 120-second window.

Three authentication failures involving the `vboxuser` account were correlated over approximately 44 seconds, generating a Level 8 security alert.

The investigation confirmed that the activity originated from an authorized lab exercise intended to validate the SOC's Linux privilege escalation detection capabilities.

The collected evidence confirms failed sudo authentication attempts but does not establish successful unauthorized privilege escalation.

**Final disposition: True Positive Detection — Authorized Security Simulation.**

## 2. Investigation Objectives

The investigation was conducted to:

1. Validate the collection of Linux sudo authentication logs.
2. Develop a custom Wazuh rule for identifying individual failed sudo authentication attempts.
3. Correlate repeated authentication failures involving the same user.
4. Generate controlled authentication failures in the lab.
5. Validate the resulting detection in Wazuh Threat Hunting.
6. Investigate the alert using original endpoint logs and SIEM metadata.
7. Document the detection, investigation findings, and final disposition.

## 3. Lab Environment

| Component | Configuration | Purpose |
|---|---|---|
| Windows Host | Windows PowerShell | Remote administration |
| Virtualization | Oracle VirtualBox | Virtual lab environment |
| SOC-SIEM-01 | Ubuntu Server, 192.168.56.10 | Wazuh SIEM |
| LINUX-SVR-01 | Ubuntu Server, 192.168.56.20 | Monitored endpoint |
| Wazuh Manager | Wazuh 4.14.10 | Event processing and correlation |
| Wazuh Agent | Agent ID 001 | Endpoint monitoring |
| Log Source | systemd-journald | Linux authentication logs |
| Decoder | PAM | Authentication event parsing |
| Target Account | vboxuser | Authorized lab user |

### Log Collection Flow

```text
LINUX-SVR-01
    |
    | sudo authentication activity
    v
systemd-journald
    |
    v
Wazuh Agent (001)
    |
    v
SOC-SIEM-01
    |
    | Custom Rules 100102 and 100101
    v
Wazuh Threat Hunting
    |
    v
SOC Investigation — INC-003
```

## 4. Detection Engineering

### 4.1 Detection Objective

Detect repeated failed sudo authentication attempts that may indicate attempts to obtain elevated privileges on a Linux endpoint.

### 4.2 Built-in Detection Rule

The initial authentication failure was identified by Wazuh's built-in PAM authentication rule.

| Property | Value |
|---|---|
| Rule ID | 5503 |
| Description | PAM: User login failed |
| Severity | Level 5 |
| Decoder | pam |

Because Rule `5503` detects general PAM authentication failures, a sudo-specific custom rule was required to distinguish sudo activity from unrelated authentication events.

### 4.3 Custom Rule 100102 — Individual Failed Sudo Authentication

```xml
<rule id="100102" level="5">
  <if_sid>5503</if_sid>
  <program_name type="pcre2">^sudo$</program_name>
  <description>SOC-DET-002: Failed sudo authentication</description>
  <group>sudo_authentication_failure,</group>
  <mitre>
    <id>T1548.003</id>
  </mitre>
</rule>
```

This rule matches PAM authentication failures when the originating program is `sudo`.

### 4.4 Custom Rule 100101 — Repeated Failed Sudo Authentication

```xml
<rule id="100101" level="8" frequency="3" timeframe="120">
  <if_matched_sid>100102</if_matched_sid>
  <same_srcuser />
  <description>SOC-DET-002: Repeated failed sudo authentication attempts by the same user</description>
  <group>sudo_authentication_failure,privilege_escalation,</group>
  <mitre>
    <id>T1548.003</id>
  </mitre>
</rule>
```

The correlation rule identifies repeated failures matched by Rule `100102`, restricted to the same source user.

| Detection Property | Configuration |
|---|---|
| Detection ID | SOC-DET-002 |
| Correlation Rule | 100101 |
| Severity | Level 8 |
| Frequency | 3 |
| Timeframe | 120 seconds |
| Correlation Field | srcuser |
| MITRE ATT&CK | T1548.003 |

The custom rules were configured in:

`/var/ossec/etc/rules/local_rules.xml`

## 5. Detection Validation

### 5.1 XML and Wazuh Configuration Validation

The custom rules were validated using:

```bash
sudo xmllint --noout /var/ossec/etc/rules/local_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t
```

Both validation commands completed without reported configuration errors.

### 5.2 Wazuh Logtest

The following representative authentication event was submitted to Wazuh Logtest:

```text
Nov 09 23:57:04 linux-svr-01 sudo[3109]: pam_unix(sudo:auth): authentication failure; logname=vboxuser uid=1000 euid=0 tty=/dev/tty1 ruser=vboxuser
```

Logtest confirmed:

- Successful syslog pre-decoding.
- Identification of the `sudo` program.
- Successful PAM decoding.
- Extraction of the `srcuser` field.
- Successful matching of custom Rule `100102`.
- Successful correlation by Rule `100101`.

The correlation test produced:

```text
id: '100101'
level: '8'
description: 'SOC-DET-002: Repeated failed sudo authentication attempts by the same user'
frequency: '3'
```

**Result: Passed.**

### 5.3 Live Detection Validation

Controlled sudo authentication failures were generated on `LINUX-SVR-01`.

The Wazuh dashboard confirmed that the endpoint generated individual failed authentication alerts and a correlated Level 8 alert.

**Result: Passed.**

## 6. Incident Timeline

The following timeline was reconstructed from the original authentication events and Wazuh alert details.

| Endpoint Time | Event | Detection |
|---|---|---|
| Nov 10, 01:30:29 | Failed sudo authentication | Individual failure |
| Nov 10, 01:30:48 | Failed sudo authentication | Individual failure |
| Nov 10, 01:31:13 | Failed sudo authentication | Rule 100101 triggered |

The three failures occurred within approximately 44 seconds.

The corresponding correlated alert appeared in the Wazuh dashboard at:

**November 9, 2026, 17:31:14.151**

The dashboard and endpoint timestamps reflect different timezone settings.

## 7. Alert Investigation

### 7.1 Alert Metadata

| Field | Observed Value |
|---|---|
| Rule ID | 100101 |
| Rule Level | 8 |
| Rule Frequency | 3 |
| Agent ID | 001 |
| Agent Name | LINUX-SVR-01 |
| Agent IP | 192.168.56.20 |
| Source User | vboxuser |
| Destination User | vboxuser |
| UID | 1000 |
| Effective UID | 0 |
| Terminal | /dev/tty1 |
| Decoder | pam |
| Program | sudo |
| Log Location | journald |
| Manager | soc-siem |

### 7.2 Original Triggering Event

The correlated alert included the following authentication failure:

```text
Nov 10 01:31:13 linux-svr-01 sudo[3665]:
pam_unix(sudo:auth): authentication failure;
logname=vboxuser uid=1000 euid=0
tty=/dev/tty1 ruser=vboxuser host= user=vboxuser
```

The `previous_output` field included preceding authentication failures at approximately 01:30:29 and 01:30:48.

This supports the conclusion that the correlation rule identified repeated failed sudo authentication attempts from the same account.

### 7.3 Source Attribution

The affected account was identified as `vboxuser`, operating on the monitored Linux endpoint.

The events were generated during an authorized lab simulation.

The `euid=0` field reflects the privileged context associated with sudo authentication processing; it does not prove that the user successfully obtained root access.

### 7.4 Authentication Outcome

The triggering events explicitly report authentication failures.

The collected evidence does not establish successful unauthorized privilege escalation.

The available investigation evidence is limited to the reviewed sudo authentication logs and Wazuh alert details. A complete assessment of all privileged activity on the host was outside the scope of this exercise.

## 8. MITRE ATT&CK Mapping

**Tactic:** Privilege Escalation / Defense Evasion  
**Technique:** T1548.003 — Sudo and Sudo Caching

Sudo enables authorized users to execute commands with elevated privileges according to system policy.

Attempts to misuse sudo or obtain elevated privileges can be relevant to privilege escalation investigations.

The custom detection was mapped to T1548.003 because it monitors failed sudo authentication attempts associated with attempts to execute privileged commands.

This mapping describes the security behavior being monitored; it does not establish malicious intent or successful privilege escalation.

## 9. Incident Response

### 9.1 Triage

The SOC investigation reviewed:

- The custom Wazuh correlation alert.
- The affected endpoint.
- The source user account.
- The original PAM authentication events.
- The correlation threshold and timeframe.
- The MITRE ATT&CK mapping.
- The authorized testing context.

### 9.2 Containment Assessment

No containment was required because the activity was generated as part of an authorized lab exercise.

No account disabling, host isolation, or privilege modification was performed as part of the incident response.

### 9.3 Final Classification

| Category | Finding |
|---|---|
| Detection Accuracy | True Positive |
| Activity Type | Authorized Security Simulation |
| Unauthorized Access | Not established |
| Successful Privilege Escalation | Not established |
| Containment Required | No |
| Incident Status | Closed |

## 10. Evidence

The following screenshots were collected during detection validation and incident investigation.

### Evidence 1 — Sudo Authentication Failure

![Sudo authentication failure](../evidence/INC-003/sudo-authentication%20failure.png)

### Evidence 2 — Additional Authentication Evidence

![Additional sudo authentication evidence](../evidence/INC-003/sudo-authentication%20failure1.png)

### Evidence 3 — Wazuh Alert Details

![Wazuh alert details](../evidence/INC-003/sudo%20alert%20details.png)

### Evidence 4 — Detection Metadata and MITRE ATT&CK

![Rule metadata and MITRE ATT&CK mapping](../evidence/INC-003/sudo%20alert%20details1.png)

**Evidence directory:** [INC-003](../evidence/INC-003/)

## 11. Recommendations

For production environments, the following controls should be considered:

1. Enforce least-privilege access through sudo policies.
2. Review sudo permissions and privileged account membership regularly.
3. Monitor repeated authentication failures involving privileged commands.
4. Investigate successful privileged activity occurring after authentication failures.
5. Implement centralized authentication logging and SIEM correlation.
6. Consider stronger authentication controls for privileged access.
7. Tune detection thresholds against legitimate administrator activity.
8. Document authorized administrative testing to support accurate alert triage.

## 12. Lessons Learned

### Detection Specificity

General PAM authentication rules can generate alerts for multiple authentication mechanisms. Restricting the detection to the `sudo` program improves detection specificity.

### Event Correlation

Correlating repeated failures from the same user provides more context than examining isolated authentication failures.

### Log Parsing

The PAM decoder successfully extracted the source username, enabling username-based correlation.

### Alert Validation

Testing detection logic with Wazuh Logtest is valuable, but live endpoint validation is necessary to confirm that the complete collection and alerting pipeline works.

### Analyst Investigation

A detection alert does not automatically establish compromise. Analysts must assess authentication outcomes, user activity, system context, and whether the behavior was authorized.

## 13. Conclusion

INC-003 successfully demonstrated the development, deployment, and validation of custom Wazuh detection rules for repeated failed sudo authentication attempts.

Custom Rule `100102` identified individual sudo authentication failures, while Rule `100101` correlated repeated failures involving the same user.

During live testing, three failed sudo authentication events were correlated within approximately 44 seconds, producing a Level 8 alert on `LINUX-SVR-01`.

The investigation confirmed that the observed activity was part of an authorized security simulation and found no evidence in the reviewed events of successful unauthorized privilege escalation.

**Final Disposition: Closed — True Positive Detection / Authorized Security Simulation.**

---

**Related Detection:** SOC-DET-002  
**Related Rules:** 100101, 100102  
**Evidence:** [INC-003 Evidence](../evidence/INC-003/)
