# Interview Notes

## 30-second explanation

"I built a home SOC monitoring lab using simulated Windows authentication data. I wrote a Python analyzer that looks for repeated failed logins, password-spraying behavior, and successful logins following repeated failures. I reviewed the detections like a junior SOC analyst, summarized affected users and source IPs, and documented remediation steps in an incident report."

## Questions you should be ready to answer

### Why are Event IDs 4624 and 4625 useful?

4624 represents a successful Windows logon and 4625 represents a failed Windows logon. They are commonly reviewed during authentication investigations.

### What is brute force?

Repeated credential attempts against an account until access is obtained.

### What is password spraying?

Trying one or a few likely passwords across many accounts instead of repeatedly attacking one account.

### Why is success after many failures important?

It can indicate that a password was eventually guessed or valid credentials were obtained.

### What could create false positives?

- users forgetting passwords
- shared IP addresses
- VPN gateways
- service accounts
- scripts or scheduled tasks
- legitimate administrative testing

### How would you improve the lab?

- ingest real Windows Event Viewer exports
- use Sysmon
- forward logs to Splunk, Wazuh, or Elastic
- add geolocation/enrichment
- add alert scoring
- build a dashboard
- correlate endpoint and network events
