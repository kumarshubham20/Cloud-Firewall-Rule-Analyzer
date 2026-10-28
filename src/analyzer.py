"""Read-only cloud firewall rule analyzer. No live firewall changes are made."""
import csv
import html
import json
from ipaddress import ip_network, ip_address
from pathlib import Path

VALID_ACTIONS = {"allow", "deny"}
VALID_PROTOCOLS = {"tcp", "udp", "icmp", "all"}
SENSITIVE_PORTS = {
    22: ("SSH", "Restrict administrative access to trusted IPs or a secure management network."),
    3389: ("RDP", "Restrict remote desktop access to trusted IPs or a secure management network."),
    3306: ("MySQL", "Keep database ports on private networks and restrict sources."),
    5432: ("PostgreSQL", "Keep database ports on private networks and restrict sources."),
    1433: ("Microsoft SQL Server", "Keep database ports on private networks and restrict sources."),
    6379: ("Redis", "Do not expose Redis publicly; use private networking and authentication."),
}
WEB_PORTS = {80, 443}


def parse_port(value):
    """Parse a single port or inclusive range such as 8000-8100."""
    if isinstance(value, int):
        start = end = value
    else:
        raw = str(value).strip()
        if "-" in raw:
            parts = raw.split("-")
            if len(parts) != 2:
                raise ValueError("port range must look like 8000-8100")
            start, end = int(parts[0]), int(parts[1])
        else:
            start = end = int(raw)
    if not (0 <= start <= 65535 and 0 <= end <= 65535):
        raise ValueError("port must be between 0 and 65535")
    if start > end:
        raise ValueError("port range start must not exceed end")
    return start, end


def load_rules(path):
    """Load firewall rules from a JSON list or CSV file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")
    if path.suffix.lower() == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("JSON input must contain a list of rules.")
        return data
    if path.suffix.lower() == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as file:
            return list(csv.DictReader(file))
    raise ValueError("Unsupported file type. Use .json or .csv.")


def validate_rule(rule, index):
    """Return a list of validation errors for one rule."""
    errors = []
    for field in ("source", "protocol", "port", "action"):
        if field not in rule or str(rule[field]).strip() == "":
            errors.append(f"Rule {index}: missing required field '{field}'.")
    if errors:
        return errors

    source = str(rule["source"]).strip()
    try:
        try:
            ip_address(source)
        except ValueError:
            ip_network(source, strict=False)
    except ValueError:
        errors.append(f"Rule {index}: '{source}' is not a valid IP address or CIDR range.")

    protocol = str(rule["protocol"]).strip().lower()
    if protocol not in VALID_PROTOCOLS:
        errors.append(f"Rule {index}: unsupported protocol '{rule['protocol']}'.")

    try:
        parse_port(rule["port"])
    except (TypeError, ValueError) as exc:
        errors.append(f"Rule {index}: invalid port: {exc}.")

    if str(rule["action"]).strip().lower() not in VALID_ACTIONS:
        errors.append(f"Rule {index}: action must be 'allow' or 'deny'.")
    return errors


def analyze_rule(rule, index):
    """Analyze one valid rule and return any matching security findings."""
    source = str(rule["source"]).strip()
    protocol = str(rule["protocol"]).strip().lower()
    start, end = parse_port(rule["port"])
    action = str(rule["action"]).strip().lower()
    rule_id = str(rule.get("id", f"RULE-{index:03d}"))
    findings = []

    try:
        network = ip_network(source, strict=False)
        public_source = network.version == 4 and network.prefixlen == 0
    except ValueError:
        public_source = False

    # This prototype reports only allow rules. Deny rules do not open access.
    if action != "allow":
        return findings

    def add(severity, title, evidence, recommendation, score):
        findings.append({
            "rule_id": rule_id,
            "severity": severity,
            "risk_score": score,
            "title": title,
            "evidence": evidence,
            "recommendation": recommendation,
        })

    public = public_source and protocol in {"tcp", "udp", "all"}
    port_label = str(start) if start == end else f"{start}-{end}"

    if public:
        if protocol == "all":
            add(
                "HIGH",
                "All protocols allowed publicly",
                f"All protocols are allowed from {source}.",
                "Allow only the minimum required protocols, ports, and trusted source ranges.",
                95,
            )

        sensitive = [
            (port, details)
            for port, details in SENSITIVE_PORTS.items()
            if start <= port <= end
        ]
        if sensitive:
            for port, (service, recommendation) in sensitive:
                add(
                    "HIGH",
                    f"Public exposure of {service}",
                    f"{protocol.upper()} port {port} is allowed from {source} by rule {rule_id}.",
                    recommendation,
                    90,
                )
        elif any(start <= port <= end for port in WEB_PORTS):
            add(
                "INFO",
                "Public web traffic allowed",
                f"{protocol.upper()} port range {port_label} is allowed from {source}.",
                "This may be intentional for a public website. Confirm the service is hardened and only required web ports are exposed.",
                15,
            )
        else:
            score = 75 if end - start >= 1000 else 60
            severity = "HIGH" if score >= 75 else "MEDIUM"
            add(
                severity,
                "Port allowed from all IPv4 addresses",
                f"{protocol.upper()} port range {port_label} is allowed from {source}.",
                "Restrict source ranges where possible and confirm every exposed port is required.",
                score,
            )
    elif end - start >= 1000:
        add(
            "MEDIUM",
            "Large port range allowed",
            f"Ports {port_label} are allowed from source {source}.",
            "Review whether the full range is needed; prefer the smallest possible port range.",
            50,
        )
    return findings


def analyze_rules(rules):
    """Analyze a list of rule objects and return a report dictionary."""
    findings, errors, valid = [], [], 0
    for index, rule in enumerate(rules, 1):
        if not isinstance(rule, dict):
            errors.append(f"Rule {index}: each rule must be an object.")
            continue
        rule_errors = validate_rule(rule, index)
        if rule_errors:
            errors.extend(rule_errors)
            continue
        valid += 1
        findings.extend(analyze_rule(rule, index))

    # Flag exact duplicate allow rules: they add maintenance complexity and can
    # cause administrators to misunderstand which rule grants access.
    seen_rules = {}
    for index, rule in enumerate(rules, 1):
        if not isinstance(rule, dict) or validate_rule(rule, index):
            continue
        action = str(rule["action"]).strip().lower()
        if action != "allow":
            continue
        try:
            source = str(ip_network(str(rule["source"]).strip(), strict=False))
            protocol = str(rule["protocol"]).strip().lower()
            start, end = parse_port(rule["port"])
        except (ValueError, TypeError):
            continue
        signature = (source, protocol, start, end, action)
        rule_id = str(rule.get("id", f"RULE-{index:03d}"))
        if signature in seen_rules:
            first_id = seen_rules[signature]
            findings.append({
                "rule_id": rule_id,
                "severity": "MEDIUM",
                "risk_score": 40,
                "title": "Duplicate allow rule",
                "evidence": (
                    f"Rule {rule_id} duplicates the source, protocol, port, "
                    f"and action of rule {first_id}."
                ),
                "recommendation": (
                    "Review both rules and remove redundant entries only after "
                    "confirming that no separate policy or ownership requires them."
                ),
            })
        else:
            seen_rules[signature] = rule_id

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
    findings.sort(
        key=lambda item: (
            severity_order.get(item["severity"], 9),
            -item["risk_score"],
        )
    )
    return {
        "summary": {
            "total_rules": len(rules),
            "valid_rules": valid,
            "invalid_rules": len(rules) - valid,
            "findings": len(findings),
            "high": sum(item["severity"] == "HIGH" for item in findings),
            "medium": sum(item["severity"] == "MEDIUM" for item in findings),
            "info": sum(item["severity"] == "INFO" for item in findings),
        },
        "findings": findings,
        "validation_errors": errors,
        "disclaimer": (
            "Educational prototype using predefined checks; "
            "not a complete cloud security audit."
        ),
    }


def write_report(report, output_path):
    """Save a report as JSON."""
    Path(output_path).write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_html_report(report, output_path):
    """Save a report as a self-contained HTML page."""
    summary = report["summary"]
    rows = []
    for finding in report["findings"]:
        cells = [
            finding["severity"],
            finding["risk_score"],
            finding["rule_id"],
            finding["title"],
            finding["evidence"],
            finding["recommendation"],
        ]
        rows.append(
            "<tr>" + "".join(
                f"<td>{html.escape(str(cell))}</td>" for cell in cells
            ) + "</tr>"
        )

    errors = "".join(
        f"<li>{html.escape(error)}</li>"
        for error in report["validation_errors"]
    ) or "<li>None</li>"

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cloud Firewall Analysis Report</title>
<style>
body {{ font: 15px/1.5 system-ui, Arial; margin: 24px; background: #f4f6fb; color: #172033; }}
main {{ max-width: 1200px; margin: auto; }}
h1 {{ color: #263c70; }}
.stats {{ display: flex; gap: 12px; flex-wrap: wrap; }}
.card {{ background: white; padding: 14px 18px; border-radius: 12px; box-shadow: 0 2px 8px #0001; }}
.tablewrap {{ overflow-x: auto; }}
table {{ border-collapse: collapse; width: 100%; background: white; }}
th, td {{ padding: 10px; border: 1px solid #dce2ed; text-align: left; vertical-align: top; }}
th {{ background: #e8eef9; }}
small {{ color: #536078; }}
</style>
</head>
<body><main>
<h1>Cloud Firewall Rule Analyzer</h1><p>Read-only analysis report</p>
<div class="stats">
<div class="card">Total rules<br><b>{summary['total_rules']}</b></div>
<div class="card">Valid rules<br><b>{summary['valid_rules']}</b></div>
<div class="card">Invalid rules<br><b>{summary['invalid_rules']}</b></div>
<div class="card">Findings<br><b>{summary['findings']}</b></div>
<div class="card">High risk<br><b>{summary['high']}</b></div>
<div class="card">Medium risk<br><b>{summary['medium']}</b></div>
</div>
<h2>Security findings</h2>
<div class="tablewrap"><table><thead><tr>
<th>Severity</th><th>Score</th><th>Rule</th><th>Issue</th><th>Evidence</th><th>Recommendation</th>
</tr></thead><tbody>
{''.join(rows) or '<tr><td colspan="6">No findings</td></tr>'}
</tbody></table></div>
<h2>Validation errors</h2><ul>{errors}</ul>
<p><small>{html.escape(report['disclaimer'])}</small></p>
</main></body></html>"""
    Path(output_path).write_text(document, encoding="utf-8")
