# INC-001 — SSH Authentication Failure Investigation

The following evidence was collected during the authorized SSH authentication simulation.

### Evidence 1 — Linux Authentication Logs

![SSH Authentication Logs](../evidence/INC-001/journal-auth-logs.png)

Shows the SSH authentication failures recorded by the Linux endpoint.

### Evidence 2 — Wazuh Threat Hunting Dashboard

![Wazuh Threat Hunting](../evidence/INC-001/wazuh-dashboard.png)

Shows centralized security monitoring and authentication alerts associated with the Linux endpoint.

### Evidence 3 — Wazuh Detection Rule 5760

![Wazuh Rule 5760](../evidence/INC-001/auth-failure-alert.png)
![Wazuh Rule 5760](../evidence/INC-001/auth-failure-alert1.png)

Shows the detected SSH authentication failure, Wazuh Rule 5760, severity level 5, and MITRE ATT&CK mapping.

**Evidence directory:** [INC-001 Evidence](../evidence/INC-001/)
