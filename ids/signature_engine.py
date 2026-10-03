
"""
Network Intrusion Detection System (IDS) Simulation

Configurable Signature-Based Detection Engine

Author: Ayush Kumar Dubey

This module applies defensive IDS rules to synthetic
network-flow records. It does not inspect live traffic.
"""

import argparse
import csv
import json
from pathlib import Path


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    BASE_DIR / "data" / "processed_network_traffic.csv"
)

RULES_FILE = (
    BASE_DIR / "ids" / "signature_rules.json"
)

OUTPUT_FILE = (
    BASE_DIR / "data" / "signature_alerts.csv"
)

ALLOWED_OPERATORS = {
    "greater_than",
    "less_than",
    "equals",
    "in"
}


# --------------------------------------------------
# RULE LOADING
# --------------------------------------------------

def load_rules(rules_path):

    rules_path = Path(rules_path)

    if not rules_path.exists():
        raise FileNotFoundError(
            f"Rules file not found: {rules_path}"
        )

    with rules_path.open(
        "r",
        encoding="utf-8"
    ) as file:

        configuration = json.load(file)

    rules = configuration.get("rules")

    if not isinstance(rules, list):
        raise ValueError(
            "The rules configuration must contain a rules list."
        )

    rule_ids = set()

    for rule in rules:

        required_fields = [
            "rule_id",
            "name",
            "description",
            "field",
            "operator",
            "threshold",
            "severity",
            "enabled"
        ]

        missing = [
            field
            for field in required_fields
            if field not in rule
        ]

        if missing:
            raise ValueError(
                f"Rule is missing fields: {missing}"
            )

        if rule["rule_id"] in rule_ids:
            raise ValueError(
                f"Duplicate rule ID: {rule['rule_id']}"
            )

        rule_ids.add(rule["rule_id"])

        if rule["operator"] not in ALLOWED_OPERATORS:
            raise ValueError(
                f"Unsupported operator: {rule['operator']}"
            )

        if not isinstance(rule["enabled"], bool):
            raise ValueError(
                f"Rule {rule['rule_id']} enabled must be boolean."
            )

        if rule["operator"] == "in" and not isinstance(
            rule["threshold"], list
        ):
            raise ValueError(
                f"Rule {rule['rule_id']} requires a list threshold."
            )

    return rules


# --------------------------------------------------
# COMPARISON ENGINE
# --------------------------------------------------

def matches_rule(value, operator, threshold):

    try:

        if operator == "greater_than":
            return float(value) > float(threshold)

        if operator == "less_than":
            return float(value) < float(threshold)

        if operator == "equals":
            return str(value) == str(threshold)

        if operator == "in":
            return int(value) in [
                int(item) for item in threshold
            ]

    except (TypeError, ValueError):
        return False

    return False


# --------------------------------------------------
# DETECTION ENGINE
# --------------------------------------------------

def detect_record(record, rules):

    matched_alerts = []

    for rule in rules:

        if not rule["enabled"]:
            continue

        field = rule["field"]

        if field not in record:
            continue

        value = record[field]

        matched = matches_rule(
            value=value,
            operator=rule["operator"],
            threshold=rule["threshold"]
        )

        if matched:

            matched_alerts.append({
                "rule_id": rule["rule_id"],
                "rule_name": rule["name"],
                "description": rule["description"],
                "severity": rule["severity"],
                "matched_field": field,
                "matched_value": value,
                "threshold": json.dumps(
                    rule["threshold"]
                )
            })

    return matched_alerts


# --------------------------------------------------
# PROCESS DATASET
# --------------------------------------------------

def run_signature_detection(
    input_path=INPUT_FILE,
    rules_path=RULES_FILE,
    output_path=OUTPUT_FILE
):

    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Processed dataset not found: {input_path}"
        )

    rules = load_rules(rules_path)

    enabled_rules = [
        rule for rule in rules
        if rule["enabled"]
    ]

    alert_columns = [
        "flow_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "label",
        "scenario_type",
        "rule_id",
        "rule_name",
        "description",
        "severity",
        "matched_field",
        "matched_value",
        "threshold"
    ]

    alerts = []

    processed_count = 0

    with input_path.open(
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        required = {
            "flow_id",
            "timestamp",
            "source_ip",
            "destination_ip",
            "source_port",
            "destination_port",
            "protocol",
            "label",
            "scenario_type"
        }

        missing = required - set(reader.fieldnames or [])

        if missing:
            raise ValueError(
                f"Processed dataset is missing columns: {sorted(missing)}"
            )

        for record in reader:

            processed_count += 1

            matched_rules = detect_record(
                record,
                enabled_rules
            )

            for match in matched_rules:

                alerts.append({
                    "flow_id": record["flow_id"],
                    "timestamp": record["timestamp"],
                    "source_ip": record["source_ip"],
                    "destination_ip": record["destination_ip"],
                    "source_port": record["source_port"],
                    "destination_port": record["destination_port"],
                    "protocol": record["protocol"],
                    "label": record["label"],
                    "scenario_type": record["scenario_type"],
                    **match
                })

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=alert_columns
        )

        writer.writeheader()

        writer.writerows(alerts)

    severity_counts = {}

    for alert in alerts:

        severity = alert["severity"]

        severity_counts[severity] = (
            severity_counts.get(severity, 0) + 1
        )

    unique_flows = {
        alert["flow_id"]
        for alert in alerts
    }

    print("\n" + "=" * 55)
    print("SIGNATURE-BASED IDS DETECTION REPORT")
    print("=" * 55)

    print(f"Records analyzed: {processed_count}")

    print(f"Enabled rules: {len(enabled_rules)}")

    print(f"Total rule matches: {len(alerts)}")

    print(f"Unique flagged flows: {len(unique_flows)}")

    print("\nSeverity distribution:")

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:

        print(
            f"{severity}: {severity_counts.get(severity, 0)}"
        )

    print("\nRule match distribution:")

    for rule in enabled_rules:

        count = sum(
            1
            for alert in alerts
            if alert["rule_id"] == rule["rule_id"]
        )

        print(
            f"{rule['rule_id']} - {rule['name']}: {count}"
        )

    print(f"\nAlerts saved to: {output_path.resolve()}")

    print("=" * 55)

    return alerts


# --------------------------------------------------
# COMMAND LINE INTERFACE
# --------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Run configurable signature-based "
            "detection on synthetic IDS data."
        )
    )

    parser.add_argument(
        "--input",
        default=str(INPUT_FILE),
        help="Processed network-flow CSV."
    )

    parser.add_argument(
        "--rules",
        default=str(RULES_FILE),
        help="JSON signature rules file."
    )

    parser.add_argument(
        "--output",
        default=str(OUTPUT_FILE),
        help="Output alerts CSV."
    )

    args = parser.parse_args()

    try:

        run_signature_detection(
            input_path=args.input,
            rules_path=args.rules,
            output_path=args.output
        )

    except (OSError, ValueError, json.JSONDecodeError) as error:

        parser.exit(
            status=1,
            message=f"\nSignature detection failed: {error}\n"
        )


if __name__ == "__main__":
    main()
    