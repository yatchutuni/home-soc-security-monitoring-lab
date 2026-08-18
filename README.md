# Home SOC Security Monitoring Lab

A beginner-friendly cybersecurity/SOC project that simulates authentication activity, analyzes logs, detects suspicious behavior, and produces an incident summary.

## What this project demonstrates

- Security log analysis
- Authentication monitoring
- Brute-force detection
- Suspicious IP identification
- Basic incident investigation
- Security documentation
- Python scripting
- SOC-style analyst workflow

## Project files

- `analyzer.py` - analyzes authentication events
- `generate_sample_logs.py` - creates a fresh simulated log dataset
- `sample_logs/auth_log.csv` - ready-to-analyze example logs
- `output/` - analysis results are written here
- `docs/LAB_WALKTHROUGH.md` - step-by-step instructions
- `docs/DETECTION_RULES.md` - detection logic
- `docs/INCIDENT_REPORT_EXAMPLE.md` - example finished incident report
- `docs/INCIDENT_REPORT_TEMPLATE.md` - blank report you can complete yourself
- `docs/INTERVIEW_NOTES.md` - how to explain the project in an interview
- `docs/RESUME_BULLETS.md` - resume wording to use after you run and understand the project

## Requirements

- Python 3.9 or newer
- No third-party Python packages required

## Quick start

### Windows

Open PowerShell in this folder and run:

```powershell
python generate_sample_logs.py
python analyzer.py
```

### macOS/Linux

Open Terminal in this folder and run:

```bash
python3 generate_sample_logs.py
python3 analyzer.py
```

The analyzer creates:

- `output/detection_results.csv`
- `output/incident_summary.txt`
- `output/ip_summary.csv`
- `output/user_summary.csv`

## What to screenshot for your portfolio

1. Project folder structure
2. Terminal after running `generate_sample_logs.py`
3. Terminal output from `analyzer.py`
4. `output/detection_results.csv`
5. `output/incident_summary.txt`
6. Your completed incident report

## Important

This package includes simulated data and an example completed incident report. Run the project yourself before describing it as your own completed project. You should be able to explain:

- what counts as a failed login
- why repeated failures are suspicious
- why multiple usernames from one IP can matter
- what threshold you used
- what remediation you recommended

## Suggested GitHub repository name

`home-soc-security-monitoring-lab`
