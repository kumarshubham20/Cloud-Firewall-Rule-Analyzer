"""Command-line entry point for the analyzer."""
import argparse

from analyzer import (
    analyze_rules,
    load_rules,
    write_html_report,
    write_report,
)


def main():
    parser = argparse.ArgumentParser(
        description="Read-only sample cloud firewall rule analyzer"
    )
    parser.add_argument("--input", default="data/sample_rules.json")
    parser.add_argument("--output", default="report.json")
    parser.add_argument("--html", default="report.html")
    args = parser.parse_args()

    try:
        rules = load_rules(args.input)
        report = analyze_rules(rules)
        write_report(report, args.output)
        write_html_report(report, args.html)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    summary = report["summary"]
    print("\n=== CLOUD FIREWALL RULE ANALYZER ===")
    print(
        f"Rules: {summary['total_rules']} | "
        f"Valid: {summary['valid_rules']} | "
        f"Invalid: {summary['invalid_rules']}"
    )
    print(
        f"Findings: {summary['findings']} | High: {summary['high']} | "
        f"Medium: {summary['medium']} | Info: {summary['info']}"
    )
    for finding in report["findings"]:
        print(
            f"\n[{finding['severity']} | score {finding['risk_score']}] "
            f"{finding['rule_id']}: {finding['title']}"
        )
        print(f"  Evidence: {finding['evidence']}")
        print(f"  Recommendation: {finding['recommendation']}")
    for error in report["validation_errors"]:
        print(f"Validation error: {error}")

    print(f"\nJSON report saved to: {args.output}")
    print(f"HTML report saved to: {args.html}")
    print("Read-only prototype: no live firewall rules were changed.")


if __name__ == "__main__":
    main()
