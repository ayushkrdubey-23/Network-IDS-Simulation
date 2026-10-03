
"""
Network Intrusion Detection System (IDS) Simulation

Statistical Anomaly Detection Engine

Author: Ayush Kumar Dubey

This module uses Z-score statistical analysis to identify
unusual patterns in synthetic network-flow data.

No real network traffic is accessed.
"""

import argparse
import csv
import math
import statistics
from collections import Counter
from pathlib import Path


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    BASE_DIR / "data" / "processed_network_traffic.csv"
)

OUTPUT_FILE = (
    BASE_DIR / "data" / "anomaly_alerts.csv"
)

# Features used for statistical analysis.
FEATURES = [
    "bytes_per_second",
    "packets_per_second",
    "failed_connection_rate",
    "syn_ratio",
    "rst_ratio",
]

# Z-score threshold.
Z_SCORE_THRESHOLD = 2.5

# Number of records required for statistical analysis.
MINIMUM_RECORDS = 10


# --------------------------------------------------
# DATA LOADING
# --------------------------------------------------

def load_dataset(input_path):

    input_path = Path(input_path)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Processed dataset not found: {input_path}"
        )

    records = []

    with input_path.open(
        "r",
        newline="",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        required_columns = {
            "flow_id",
            "timestamp",
            "source_ip",
            "destination_ip",
            "label",
            "scenario_type",
            *FEATURES,
        }

        missing = required_columns - set(
            reader.fieldnames or []
        )

        if missing:
            raise ValueError(
                "Missing required columns: "
                + ", ".join(sorted(missing))
            )

        for row_number, record in enumerate(
            reader,
            start=2
        ):

            try:

                for feature in FEATURES:

                    value = float(record[feature])

                    if not math.isfinite(value):
                        raise ValueError(
                            f"{feature} must be finite"
                        )

                    record[feature] = value

                records.append(record)

            except (ValueError, TypeError) as error:

                raise ValueError(
                    f"Invalid feature data at row {row_number}: {error}"
                ) from error

    if len(records) < MINIMUM_RECORDS:
        raise ValueError(
            f"At least {MINIMUM_RECORDS} records are required."
        )

    return records


# --------------------------------------------------
# STATISTICAL BASELINE
# --------------------------------------------------

def calculate_baseline(records):

    baseline = {}

    for feature in FEATURES:

        values = [
            record[feature]
            for record in records
        ]

        mean_value = statistics.mean(values)

        standard_deviation = statistics.pstdev(
            values
        )

        baseline[feature] = {
            "mean": mean_value,
            "standard_deviation": standard_deviation,
        }

    return baseline


# --------------------------------------------------
# Z-SCORE CALCULATION
# --------------------------------------------------

def calculate_z_score(value, mean, standard_deviation):

    if standard_deviation == 0:
        return 0.0

    return (
        value - mean
    ) / standard_deviation


# --------------------------------------------------
# ANOMALY DETECTION
# --------------------------------------------------

def detect_anomalies(
    records,
    baseline,
    threshold=Z_SCORE_THRESHOLD
):

    alerts = []

    for record in records:

        anomalous_features = []

        highest_absolute_z_score = 0.0

        for feature in FEATURES:

            mean_value = baseline[feature]["mean"]

            standard_deviation = baseline[feature][
                "standard_deviation"
            ]

            z_score = calculate_z_score(
                value=record[feature],
                mean=mean_value,
                standard_deviation=standard_deviation
            )

            absolute_z_score = abs(z_score)

            if absolute_z_score > highest_absolute_z_score:
                highest_absolute_z_score = absolute_z_score

            if absolute_z_score >= threshold:

                anomalous_features.append({
                    "feature": feature,
                    "observed_value": round(
                        record[feature], 4
                    ),
                    "z_score": round(z_score, 4),
                })

        if anomalous_features:

            if highest_absolute_z_score >= 4:
                severity = "HIGH"

            elif highest_absolute_z_score >= 3:
                severity = "MEDIUM"

            else:
                severity = "LOW"

            alerts.append({
                "flow_id": record["flow_id"],
                "timestamp": record["timestamp"],
                "source_ip": record["source_ip"],
                "destination_ip": record["destination_ip"],
                "label": record["label"],
                "scenario_type": record["scenario_type"],
                "severity": severity,
                "anomalous_features": anomalous_features,
                "highest_absolute_z_score": round(
                    highest_absolute_z_score, 4
                ),
            })

    return alerts


# --------------------------------------------------
# SAVE ANOMALY ALERTS
# --------------------------------------------------

def save_alerts(alerts, output_path):

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    fieldnames = [
        "flow_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "label",
        "scenario_type",
        "severity",
        "anomalous_features",
        "highest_absolute_z_score",
    ]

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for alert in alerts:

            output_record = dict(alert)

            output_record["anomalous_features"] = "; ".join(
                (
                    f"{item['feature']}: "
                    f"value={item['observed_value']}, "
                    f"z={item['z_score']}"
                )
                for item in alert["anomalous_features"]
            )

            writer.writerow(output_record)


# --------------------------------------------------
# MAIN ANALYSIS
# --------------------------------------------------

def run_anomaly_detection(
    input_path=INPUT_FILE,
    output_path=OUTPUT_FILE,
    threshold=Z_SCORE_THRESHOLD
):

    if threshold <= 0:
        raise ValueError(
            "Z-score threshold must be greater than zero."
        )

    records = load_dataset(input_path)

    baseline = calculate_baseline(records)

    alerts = detect_anomalies(
        records=records,
        baseline=baseline,
        threshold=threshold
    )

    save_alerts(
        alerts=alerts,
        output_path=output_path
    )

    severity_counts = Counter(
        alert["severity"]
        for alert in alerts
    )

    normal_alerts = sum(
        1
        for alert in alerts
        if alert["label"] == "NORMAL"
    )

    suspicious_alerts = sum(
        1
        for alert in alerts
        if alert["label"] == "SUSPICIOUS"
    )

    print("\n" + "=" * 55)
    print("STATISTICAL ANOMALY DETECTION REPORT")
    print("=" * 55)

    print(f"Records analyzed: {len(records)}")

    print(f"Z-score threshold: {threshold}")

    print(f"Anomalous flows: {len(alerts)}")

    print(f"Normal-labelled alerts: {normal_alerts}")

    print(
        f"Suspicious-labelled alerts: {suspicious_alerts}"
    )

    print("\nSeverity distribution:")

    for severity in ["HIGH", "MEDIUM", "LOW"]:

        print(
            f"{severity}: {severity_counts.get(severity, 0)}"
        )

    print("\nStatistical baseline:")

    for feature, values in baseline.items():

        print(
            f"{feature}: "
            f"mean={values['mean']:.4f}, "
            f"std={values['standard_deviation']:.4f}"
        )

    print(
        f"\nAlerts saved to: {Path(output_path).resolve()}"
    )

    print("=" * 55)

    return alerts, baseline


# --------------------------------------------------
# COMMAND LINE INTERFACE
# --------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Run statistical anomaly detection "
            "on synthetic IDS network-flow data."
        )
    )

    parser.add_argument(
        "--input",
        default=str(INPUT_FILE),
        help="Processed network-flow CSV."
    )

    parser.add_argument(
        "--output",
        default=str(OUTPUT_FILE),
        help="Output anomaly alerts CSV."
    )

    parser.add_argument(
        "--threshold",
        type=float,
        default=Z_SCORE_THRESHOLD,
        help="Z-score threshold for anomaly detection."
    )

    args = parser.parse_args()

    try:

        run_anomaly_detection(
            input_path=args.input,
            output_path=args.output,
            threshold=args.threshold
        )

    except (OSError, ValueError) as error:

        parser.exit(
            status=1,
            message=f"\nAnomaly detection failed: {error}\n"
        )


if __name__ == "__main__":
    main()