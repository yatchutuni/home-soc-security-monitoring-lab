# Incident Report

## Incident Title

Suspicious Authentication Activity on WIN11-LAB

## Date

August 18, 2026

## Analyst

Yuvraj Atchutuni

## Severity

Critical

## Executive Summary

Authentication logs from the simulated Windows endpoint `WIN11-LAB` were analyzed for suspicious login activity. The investigation identified repeated failed login attempts against the `administrator` account from source IP `10.10.10.55`. Additional activity consistent with password spraying was detected from source IP `172.16.5.99`, which attempted authentication against multiple user accounts. A successful administrator login was later observed from `10.10.10.55` after 12 failed attempts, increasing the incident severity because the activity could indicate credential compromise.

## Evidence Reviewed

* Simulated Windows authentication logs
* Automated detection results
* Source IP authentication summary
* User authentication summary
* Windows authentication Event IDs 4624 and 4625

## Timeline

| Time     | Event                                                                                        |
| -------- | -------------------------------------------------------------------------------------------- |
| 10:05:00 | Failed authentication attempts against the `administrator` account began from `10.10.10.55`. |
| 10:08:18 | Twelfth failed administrator login attempt was observed from `10.10.10.55`.                  |
| 10:10:00 | Successful login to the `administrator` account occurred from `10.10.10.55`.                 |
| 10:50:00 | Failed authentication attempts against multiple accounts began from `172.16.5.99`.           |
| 10:52:05 | Password-spraying activity from `172.16.5.99` ended after targeting six usernames.           |

## Key Findings

### Finding 1 - Potential Brute-Force Attack

Source IP `10.10.10.55` generated 12 failed login attempts against the `administrator` account within approximately four minutes.

This activity exceeded the lab detection threshold of five failed authentication attempts within ten minutes and was classified as a potential brute-force attack.

**Severity:** High

### Finding 2 - Possible Password Spraying

Source IP `172.16.5.99` attempted authentication against six different usernames:

* administrator
* alex
* guest
* jamie
* morgan
* taylor

The use of one source IP to attempt authentication against multiple accounts is consistent with password-spraying behavior.

**Severity:** Medium

### Finding 3 - Successful Login Following Repeated Failures

At approximately 10:10:00, a successful login to the `administrator` account occurred from source IP `10.10.10.55` after 12 failed authentication attempts.

Because the successful authentication followed repeated failures from the same source IP against the same account, this event was treated as the highest-priority finding.

**Severity:** Critical

## Indicators of Compromise / Suspicious Indicators

* Suspicious source IP: `10.10.10.55`
* Password-spraying source IP: `172.16.5.99`
* Targeted privileged account: `administrator`
* Additional targeted accounts: `alex`, `guest`, `jamie`, `morgan`, `taylor`
* Windows Event ID `4625`: Failed logon
* Windows Event ID `4624`: Successful logon
* Host: `WIN11-LAB`

## Recommended Remediation

1. Investigate whether `10.10.10.55` is an authorized system or source.
2. Reset the administrator account password if the activity is unauthorized.
3. Enable multi-factor authentication for privileged accounts.
4. Configure account-lockout or authentication rate-limiting policies.
5. Review authentication activity from `172.16.5.99` across all affected accounts.
6. Block or restrict suspicious source IP addresses where appropriate.
7. Review other systems for authentication attempts from the same suspicious IP addresses.
8. Continue monitoring for additional failed or successful authentication attempts involving the affected accounts.

## Lessons Learned

This investigation demonstrated how authentication events can be correlated using timestamps, usernames, source IP addresses, and login outcomes to identify suspicious behavior. Repeated failures against one account can indicate brute-force activity, while failures across multiple accounts from the same source can indicate password spraying. A successful authentication following numerous failed attempts requires additional investigation because it may indicate that credentials were successfully guessed or compromised.

The lab also demonstrated the importance of combining automated detection with analyst review before determining incident severity and recommending remediation.
