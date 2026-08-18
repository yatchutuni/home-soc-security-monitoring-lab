# Detection Rules

## Rule 1 - Potential brute-force attack

**Condition:** Five or more failed authentication attempts against the same username from the same source IP within 10 minutes.

**Severity:** High

**Why it matters:** Repeated password attempts can indicate credential guessing.

## Rule 2 - Possible password spraying

**Condition:** One source IP attempts failed authentication against four or more distinct usernames.

**Severity:** Medium

**Why it matters:** Password spraying uses a small number of common passwords against many accounts.

## Rule 3 - Successful login after repeated failures

**Condition:** A successful login occurs for the same username and source IP after at least five recent failed attempts.

**Severity:** Critical

**Why it matters:** This can indicate that an attacker eventually guessed or obtained valid credentials.

## Tuning considerations

Real SOC detections should account for:

- shared VPN/NAT addresses
- service accounts
- password-management problems
- scheduled jobs
- legitimate administrators
- expected geographic locations
- user baseline behavior

Detection thresholds in this lab are intentionally simple for learning.
