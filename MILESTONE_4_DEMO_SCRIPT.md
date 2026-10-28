# Milestone 4 Demo Script (2–3 minutes)

1. Introduce the project: “This Python tool analyzes sample firewall rules, validates their fields, detects selected risky configurations, and recommends improvements.”
2. Start the dashboard with `python src/webapp.py` and open `http://127.0.0.1:8000`.
3. Click **Analyze rules** and explain the counts and findings.
4. Show the public SSH rule on TCP port 22 from `0.0.0.0/0` and explain why open remote administration deserves review.
5. Show the PostgreSQL finding on port 5432.
6. Explain that public HTTPS can be intentional, so the prototype classifies it as informational.
7. Change one port to `70000`, analyze again, and show the validation error. Click **Restore sample** and re-analyze.
8. Download the JSON report and, if useful, open `report.html`.
9. Conclude: “The prototype runs locally, uses predefined checks and does not change live cloud firewall settings.”

Record the demonstration on your own computer. This script is not a video recording.
