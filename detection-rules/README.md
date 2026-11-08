# SOC Detection Engineering

This directory contains custom security detection rules developed and validated in the Enterprise SOC Threat Detection and Incident Response Lab.

## SOC-DET-001 — Repeated SSH Authentication Failures

**Detection file:** [ssh-repeated-authentication.xml](ssh-repeated-authentication.xml)

### Detection Objective

Identify repeated SSH authentication failures originating from the same source IP address within a short period.

This detection provides an early-warning mechanism for potential SSH password-guessing activity.

### Detection Logic

The rule correlates SSH authentication failure events identified by Wazuh Rule `5760`.

It generates a Level 8 alert when the configured frequency threshold of five matching events is reached within 120 seconds, with correlation restricted to the same source IP.

### MITRE ATT&CK

- **Tactic:** Credential Access
- **Technique:** T1110 — Brute Force

### Validation Results

| Test | Result |
|---|---|
| XML syntax validation | Passed |
| SSH event decoding | Passed |
| Base Rule 5760 matching | Passed |
| Custom Rule 100100 Logtest | Passed |
| Live endpoint detection | Passed |
| Alert visible in Wazuh Threat Hunting | Passed |

### Observed Live Test

Six failed SSH authentication attempts were generated during an authorized lab simulation.

- Source IP: `192.168.56.10`
- Destination IP: `192.168.56.20`
- Target account: `vboxuser`
- Alert rule: `100100`
- Severity: Level 8

The custom detection generated a live Wazuh alert. The investigation found no successful SSH authentication in the reviewed incident window.

### Deployment

1. Back up the existing Wazuh local rules file.
2. Add the custom rule to `/var/ossec/etc/rules/local_rules.xml`, inside an existing rule group, or install the standalone XML file as a separate custom rules file.
3. Validate the rule using `wazuh-logtest`.
4. Restart `wazuh-manager` after successful validation.
5. Confirm that the manager and connected agents are healthy.
6. Perform controlled testing and verify alerts in Wazuh Threat Hunting.

Do not modify Wazuh's built-in SSH rules directly.

### Investigation Reference

[INC-002 — SSH Brute-Force Detection and Investigation](../investigations/INC-002-ssh-brute-force.md)

### Production Considerations

The five-event threshold was selected for lab validation and has not been tuned against a production authentication baseline.

Before production use, assess false positives, administrator login patterns, authorized vulnerability testing, service accounts, and potential differences in log formats.

The detection identifies suspicious authentication patterns but does not independently prove malicious intent or successful compromise.
