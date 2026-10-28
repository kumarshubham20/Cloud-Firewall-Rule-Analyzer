# Cloud Firewall Rule Analyzer Using Python — Milestone 4

A local, read-only educational prototype that analyzes sample firewall rules, validates inputs, finds selected risky configurations, assigns severity and scores, and produces JSON/HTML reports with a browser dashboard.

## Requirements
- Python 3.10 or newer recommended
- No third-party Python packages required

## Start the browser dashboard
From this repository folder, run:

```powershell
python src/webapp.py
```

Then open http://127.0.0.1:8000 in your browser. Click **Analyze rules** to show findings and recommendations. Edit the JSON sample to try other rules. Click **Download JSON report** to export a report.

Keep the terminal open while the dashboard is running. Press Ctrl+C to stop it.

## Run from the command line

```powershell
python src/main.py --input data/sample_rules.json --output report.json --html report.html
```

Try CSV input:

```powershell
python src/main.py --input data/sample_rules.csv --output csv_report.json --html csv_report.html
```

Try invalid examples:

```powershell
python src/main.py --input data/invalid_rules.json --output invalid_report.json --html invalid_report.html
```

## Run automated tests

```powershell
python -m unittest discover -s tests -v
```

The current local test suite contains eight unit tests for selected analysis, validation, file-loading, and reporting behaviours.

## Project structure
- `src/analyzer.py`: input loading, validation, predefined security checks, severity scoring, JSON/HTML reports
- `src/main.py`: command-line entry point
- `src/webapp.py`: local browser dashboard and HTTP endpoint
- `data/sample_rules.json`: main demo rules
- `data/sample_rules.csv`: CSV demo rules
- `data/invalid_rules.json`: intentionally invalid examples
- `tests/test_analyzer.py`: automated tests
- `MILESTONE_4_DEMO_SCRIPT.md`: demonstration outline

## Data flow
Browser/JSON/CSV input → input validation → security rule checks → severity and risk score → findings/recommendations → JSON or HTML report.

## Scope and safety
This is a local educational prototype. It does not connect to AWS, Azure, or Google Cloud and does not modify live firewall configurations. Findings and numeric scores are based on simple predefined teaching checks, not a complete security audit or certified scoring standard. Review results in their network context before taking action.
