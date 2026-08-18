# Incident Report Example

## Incident Title

Suspicious Authentication Activity on WIN11-LAB

## Date

August 18, 2026

## Severity

Critical

## Executive Summary

Authentication logs from the simulated Windows endpoint `WIN11-LAB` were reviewed for suspicious login behavior. The analysis identified repeated failed login attempts against the `administrator` account from source IP `10.10.10.55`, activity consistent with password spraying from `172.16.5.99`, and a successful administrator login following repeated failures from `10.10.10.55`.

The successful authentication after numerous failures increased the severity because it could represent credential compromise.

## Evidence Reviewed

- Simulated authentication log
- Failed-login counts by source IP
- Username authentication summary
- Automated detection output

## Key Findings

### Finding 1 - Repeated administrator login failures

Source IP `10.10.10.55` generated numerous failed login attempts against the `administrator` account in a short period.

This behavior exceeded the lab brute-force threshold.

### Finding 2 - Multiple accounts targeted

Source IP `172.16.5.99` attempted authentication against several different usernames.

This pattern is consistent with password-spraying behavior.

### Finding 3 - Successful login following failures

A successful login to the `administrator` account was observed from `10.10.10.55` after repeated failures.

This was treated as the highest-priority event because a successful authentication after sustained failures may indicate compromised credentials.

## Indicators

- Suspicious source IP: `10.10.10.55`
- Password-spray source IP: `172.16.5.99`
- High-value account: `administrator`
- Windows-style failed logon event: `4625`
- Windows-style successful logon event: `4624`

## Recommended Actions

1. Validate whether `10.10.10.55` is an authorized system.
2. Reset the administrator password if the activity is unauthorized.
3. Enable MFA for privileged accounts.
4. Review account lockout and sign-in rate-limiting controls.
5. Block the suspicious source IP if appropriate.
6. Review other systems for authentication from the same source.
7. Continue monitoring for additional failed or successful authentication attempts.

## Lessons Learned

Authentication failures become more meaningful when correlated by source IP, username, time window, and subsequent successful access. A SOC analyst should investigate not only individual failed events but also the sequence of events surrounding them.
