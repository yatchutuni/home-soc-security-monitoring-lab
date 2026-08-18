# Lab Walkthrough

## Objective

Act as a junior SOC analyst reviewing authentication activity for a Windows endpoint.

You will:

1. Generate simulated Windows-style authentication logs.
2. Analyze them using Python.
3. Identify brute-force and password-spraying behavior.
4. Identify a suspicious successful login after repeated failures.
5. Review source-IP and username statistics.
6. Write an incident report.

## Step 1 - Verify Python

Windows:

```powershell
python --version
```

macOS/Linux:

```bash
python3 --version
```

Use Python 3.9+.

## Step 2 - Generate the dataset

Windows:

```powershell
python generate_sample_logs.py
```

macOS/Linux:

```bash
python3 generate_sample_logs.py
```

Open:

`sample_logs/auth_log.csv`

Important fields:

- `timestamp`
- `host`
- `username`
- `source_ip`
- `status`
- `event_id`
- `logon_type`
- `message`

Windows Event IDs used in this simulation:

- 4624 = successful logon
- 4625 = failed logon

## Step 3 - Run the analyzer

Windows:

```powershell
python analyzer.py
```

macOS/Linux:

```bash
python3 analyzer.py
```

## Step 4 - Review detections

Open:

`output/detection_results.csv`

Look for:

- repeated failures from one source IP
- one source IP targeting several usernames
- a successful login after repeated failures

## Step 5 - Investigate source IPs

Open:

`output/ip_summary.csv`

Questions to answer:

- Which IP generated the most failures?
- Which IP attempted the most unique usernames?
- Did any suspicious IP later authenticate successfully?

## Step 6 - Investigate affected accounts

Open:

`output/user_summary.csv`

Questions:

- Which account had the most failed attempts?
- Which accounts were targeted by password spraying?
- Was an administrator account involved?

## Step 7 - Write your report

Use:

`docs/INCIDENT_REPORT_TEMPLATE.md`

Do not just copy the example. Write the findings in your own words after reviewing the output.

## Step 8 - Portfolio evidence

Take screenshots of:

- terminal output
- detection results
- incident summary
- your final report

You can upload the project to GitHub after replacing the example report with your own completed report.

## Optional next step: real Windows Event Viewer practice

On a Windows VM:

1. Open Event Viewer.
2. Go to `Windows Logs > Security`.
3. Filter for Event IDs `4624,4625`.
4. Review successful and failed sign-in events.
5. Export selected events if desired.

Do not expose private information from your real computer in a public GitHub repo.
