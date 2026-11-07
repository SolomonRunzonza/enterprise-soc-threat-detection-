# INC-001 — SSH Authentication Failure Investigation

## 1. Incident Summary

| Field | Details |
|---|---|
| Case ID | INC-001 |
| Investigation Date | November 7, 2026 |
| Environment | Enterprise SOC VirtualBox Lab |
| Detection Platform | Wazuh SIEM 4.14 |
| Affected Endpoint | LINUX-SVR-01 |
| Endpoint IP | 192.168.56.20 |
| Source IP | 192.168.56.1 |
| Target Account | vboxuser |
| Detection Rule | 5760 |
| Rule Level | 5 |
| Case Classification | Authorized security simulation |
| Investigation Status | Initial detection verified; case documentation completed |

## 2. Business Scenario

A fictional enterprise operates Linux servers that administrators access remotely using SSH.

The Security Operations Center is responsible for monitoring authentication activity, identifying suspicious login patterns, investigating potential unauthorized access, and determining whether escalation is necessary.

This investigation evaluates the SOC's ability to detect and analyze failed SSH authentication attempts.

## 3. Investigation Objectives

- Generate controlled failed SSH authentication attempts.
- Verify that authentication events are recorded on the endpoint.
- Confirm centralized log collection by Wazuh.
- Examine security alert metadata and original log evidence.
- Identify the source, destination, account, and detection rule.
- Classify the activity and document the findings.

## 4. Detection and Evidence

### 4.1 Endpoint Authentication Evidence

Controlled incorrect SSH passwords were submitted from the Windows host to the monitored Linux server.

The endpoint recorded authentication failures in its systemd journal.

Example observed event:

```text
Failed password for vboxuser from 192.168.56.1 port 50611 ssh2
```

### 4.2 Wazuh Alert Details

| Field | Observed Value |
|---|---|
| Agent ID | 001 |
| Agent Name | LINUX-SVR-01 |
| Log Source | journald |
| Decoder | sshd |
| Source IP | 192.168.56.1 |
| Source Port | 50611 |
| Target User | vboxuser |
| Rule ID | 5760 |
| Rule Description | sshd: authentication failed. |
| Rule Level | 5 |
| Rule Groups | syslog, sshd, authentication_failed |

**Event timestamp:** November 7, 2026, 10:48:26.818, as displayed in the Wazuh dashboard.

**Original log timestamp:** November 7, 2026, 18:48:26, as recorded in the event.

The difference is consistent with UTC and Pacific Standard Time display settings.

## 5. MITRE ATT&CK Mapping

Wazuh associated the alert with:

| Technique | Description |
|---|---|
| T1110.001 | Brute Force: Password Guessing |
| T1021.004 | Remote Services: SSH |

The mappings describe behaviors associated with credential-access attempts and SSH remote access. They do not independently establish malicious intent or successful lateral movement.

## 6. Investigation Analysis

The investigation established that:

1. The Linux endpoint was reachable through the host-only network.
2. OpenSSH Server was installed and running.
3. The Windows host initiated SSH authentication attempts.
4. Incorrect passwords generated failed authentication records.
5. The Wazuh agent forwarded relevant security telemetry.
6. Wazuh decoded the SSH event and generated Rule 5760.
7. The dashboard displayed the authentication alert and associated MITRE ATT&CK classifications.

The dashboard also showed multiple authentication-failure alerts during the selected period. However, these counts were not individually correlated to distinct login attempts.

A successful SSH login was observed earlier during testing, but the available evidence does not establish unauthorized access.

## 7. SOC Analyst Assessment

**Detection outcome:** True positive for failed SSH authentication.

**Activity classification:** Authorized security testing.

**Security impact:** No confirmed compromise.

**Escalation decision:** No escalation required for the known authorized test.

**Limitations:** The investigation verified a representative Wazuh alert but did not exhaustively correlate all related authentication events or establish a complete session-by-session timeline.

## 8. Recommended Security Controls

For a production enterprise environment, the SOC should consider:

- SSH key-based authentication.
- Disabling password authentication after validating operational requirements.
- Restricting SSH access through firewalls or approved management networks.
- Monitoring repeated authentication failures.
- Alert correlation and appropriate escalation thresholds.
- Reviewing successful logins following repeated failures.
- Applying least-privilege access and maintaining audit logs.

## 9. Lessons Learned

This investigation demonstrated how authentication activity moves from an endpoint into a centralized security monitoring platform.

Practical skills exercised included Linux administration, log collection verification, SIEM alert investigation, event field analysis, and MITRE ATT&CK mapping.

It also highlighted the importance of distinguishing confirmed security observations from assumptions about malicious activity.

## 10. Final Disposition

**Case disposition: Closed — Authorized Simulation**

The observed failed SSH authentication activity was intentionally generated in the laboratory.

Wazuh successfully detected the authentication failure using Rule 5760 at level 5.

No unauthorized access or compromise was established from the available evidence.

Further exercises will evaluate repeated authentication failures, event correlation, and custom detection rules.
