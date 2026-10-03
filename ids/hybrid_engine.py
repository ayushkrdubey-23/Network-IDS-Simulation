
"""
Network Intrusion Detection System (IDS) Simulation

Hybrid Detection and Risk Scoring Engine

Author: Ayush Kumar Dubey

Combines:
1. Signature-based detection
2. Statistical anomaly detection
3. Machine learning predictions

All analysis uses synthetic network-flow records.
"""

import argparse
import csv
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_FILE = (
    BASE_DIR / "data" / "processed_network_traffic.csv"
)

SIGNATURE_FILE = (
    BASE_DIR / "data" / "signature_alerts.csv"
)

ANOMALY_FILE = (
    BASE_DIR / "data" / "anomaly_alerts.csv"
)

MODEL_DIR = BASE_DIR / "models"

OUTPUT_FILE = (
    BASE_DIR / "data" / "hybrid_alerts.csv"
)

FEATURE_COLUMNS = [
    "source_port",
    "destination_port",
    "packet_count",
    "byte_count",
    "duration_seconds",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
    "average_packet_size",
    "bytes_per_second",
    "packets_per_second",
    "failed_connection_rate",
    "syn_ratio",
    "rst_ratio",
]

MODEL_NAMES = [
    "logistic_regression",
    "random_forest",
    "isolation_forest",
]

# Maximum contribution from each detection source.
SIGNATURE_WEIGHT = 40
ANOMALY_WEIGHT = 25
ML_WEIGHT = 35

# Risk thresholds.
RISK_THRESHOLDS = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
}


# --------------------------------------------------
# INPUT VALIDATION
# --------------------------------------------------

def validate_input_files():

    required_files = [
        DATA_FILE,
        SIGNATURE_FILE,
        ANOMALY_FILE,
    ]

    for file_path in required_files:

        if not file_path.exists():
            raise FileNotFoundError(
                f"Required file not found: {file_path}"
            )

    for model_name in MODEL_NAMES:

        model_path = (
            MODEL_DIR / f"{model_name}.joblib"
        )

        if not model_path.exists():
            raise FileNotFoundError(
                f"Model not found: {model_path}"
            )


# --------------------------------------------------
# LOAD INPUT DATA
# --------------------------------------------------

def load_csv(path):

    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    return pd.read_csv(path)


def load_detection_inputs():

    traffic = load_csv(DATA_FILE)

    signatures = load_csv(SIGNATURE_FILE)

    anomalies = load_csv(ANOMALY_FILE)

    required_columns = (
        FEATURE_COLUMNS
        + ["flow_id", "timestamp", "source_ip",
           "destination_ip", "label", "scenario_type"]
    )

    missing = [
        column
        for column in required_columns
        if column not in traffic.columns
    ]

    if missing:
        raise ValueError(
            "Traffic data is missing columns: "
            + ", ".join(missing)
        )

    return traffic, signatures, anomalies


# --------------------------------------------------
# MACHINE LEARNING PREDICTIONS
# --------------------------------------------------

def load_models():

    models = {}

    for model_name in MODEL_NAMES:

        model_path = (
            MODEL_DIR / f"{model_name}.joblib"
        )

        models[model_name] = joblib.load(
            model_path
        )

    return models


def get_ml_predictions(traffic, models):

    X = traffic[FEATURE_COLUMNS].copy()

    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    )

    predictions = {}

    for model_name, model in models.items():

        raw_predictions = model.predict(X)

        if model_name == "isolation_forest":

            binary_predictions = np.where(
                raw_predictions == -1,
                1,
                0
            )

        else:

            binary_predictions = raw_predictions.astype(int)

        predictions[model_name] = binary_predictions

    return predictions


# --------------------------------------------------
# SIGNATURE ALERT AGGREGATION
# --------------------------------------------------

def aggregate_signature_alerts(signatures):

    if signatures.empty:
        return {}

    required = {"flow_id", "rule_id", "severity"}

    if not required.issubset(signatures.columns):
        raise ValueError(
            "Signature alert file has missing columns."
        )

    grouped = {}

    for _, row in signatures.iterrows():

        flow_id = str(row["flow_id"])

        grouped.setdefault(
            flow_id,
            []
        ).append({
            "rule_id": str(row["rule_id"]),
            "rule_name": str(row["rule_name"]),
            "severity": str(row["severity"]).upper(),
        })

    return grouped


# --------------------------------------------------
# ANOMALY ALERT AGGREGATION
# --------------------------------------------------

def aggregate_anomaly_alerts(anomalies):

    if anomalies.empty:
        return {}

    required = {"flow_id", "severity"}

    if not required.issubset(anomalies.columns):
        raise ValueError(
            "Anomaly alert file has missing columns."
        )

    grouped = {}

    for _, row in anomalies.iterrows():

        flow_id = str(row["flow_id"])

        grouped[flow_id] = {
            "severity": str(row["severity"]).upper(),
            "highest_absolute_z_score": float(
                row["highest_absolute_z_score"]
            ),
        }

    return grouped


# --------------------------------------------------
# RISK SCORING
# --------------------------------------------------

def calculate_signature_score(matched_rules):

    if not matched_rules:
        return 0

    severity_points = {
        "LOW": 10,
        "MEDIUM": 20,
        "HIGH": 30,
        "CRITICAL": 40,
    }

    highest_score = max(
        severity_points.get(
            rule["severity"], 0
        )
        for rule in matched_rules
    )

    # Cap signature contribution.
    return min(
        highest_score,
        SIGNATURE_WEIGHT
    )


def calculate_anomaly_score(anomaly):

    if anomaly is None:
        return 0

    severity_points = {
        "LOW": 10,
        "MEDIUM": 18,
        "HIGH": 25,
    }

    return min(
        severity_points.get(
            anomaly["severity"], 0
        ),
        ANOMALY_WEIGHT
    )


def calculate_ml_score(ml_predictions):

    votes = sum(
        int(prediction)
        for prediction in ml_predictions.values()
    )

    if not ml_predictions:
        return 0

    proportion = votes / len(ml_predictions)

    return round(
        proportion * ML_WEIGHT
    )


def calculate_risk_score(
    matched_rules,
    anomaly,
    ml_predictions
):

    signature_score = calculate_signature_score(
        matched_rules
    )

    anomaly_score = calculate_anomaly_score(
        anomaly
    )

    ml_score = calculate_ml_score(
        ml_predictions
    )

    total_score = min(
        100,
        signature_score
        + anomaly_score
        + ml_score
    )

    return {
        "signature_score": signature_score,
        "anomaly_score": anomaly_score,
        "ml_score": ml_score,
        "risk_score": total_score,
    }


# --------------------------------------------------
# RISK CLASSIFICATION
# --------------------------------------------------

def classify_risk(score):

    if score >= RISK_THRESHOLDS["HIGH"]:
        return "HIGH"

    if score >= RISK_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"

    if score >= RISK_THRESHOLDS["LOW"]:
        return "LOW"

    return "INFO"


# --------------------------------------------------
# HYBRID DETECTION
# --------------------------------------------------

def run_hybrid_detection():

    validate_input_files()

    traffic, signatures, anomalies = (
        load_detection_inputs()
    )

    models = load_models()

    ml_predictions = get_ml_predictions(
        traffic,
        models
    )

    signature_map = aggregate_signature_alerts(
        signatures
    )

    anomaly_map = aggregate_anomaly_alerts(
        anomalies
    )

    alerts = []

    for index, record in traffic.iterrows():

        flow_id = str(record["flow_id"])

        matched_rules = signature_map.get(
            flow_id,
            []
        )

        anomaly = anomaly_map.get(
            flow_id
        )

        model_predictions = {
            name: int(values[index])
            for name, values in ml_predictions.items()
        }

        scores = calculate_risk_score(
            matched_rules,
            anomaly,
            model_predictions
        )

        risk_level = classify_risk(
            scores["risk_score"]
        )

        is_flagged = (
            scores["risk_score"] >= 25
        )

        alerts.append({
            "flow_id": flow_id,
            "timestamp": record["timestamp"],
            "source_ip": record["source_ip"],
            "destination_ip": record["destination_ip"],
            "label": record["label"],
            "scenario_type": record["scenario_type"],
            "signature_matches": len(matched_rules),
            "matched_rule_ids": ";".join(
                rule["rule_id"]
                for rule in matched_rules
            ),
            "is_anomaly": anomaly is not None,
            "logistic_regression_prediction": (
                model_predictions["logistic_regression"]
            ),
            "random_forest_prediction": (
                model_predictions["random_forest"]
            ),
            "isolation_forest_prediction": (
                model_predictions["isolation_forest"]
            ),
            **scores,
            "risk_level": risk_level,
            "is_flagged": is_flagged,
        })

    output_columns = [
        "flow_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "label",
        "scenario_type",
        "signature_matches",
        "matched_rule_ids",
        "is_anomaly",
        "logistic_regression_prediction",
        "random_forest_prediction",
        "isolation_forest_prediction",
        "signature_score",
        "anomaly_score",
        "ml_score",
        "risk_score",
        "risk_level",
        "is_flagged",
    ]

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=output_columns
        )

        writer.writeheader()

        writer.writerows(alerts)

    risk_counts = {}

    for alert in alerts:

        level = alert["risk_level"]

        risk_counts[level] = (
            risk_counts.get(level, 0) + 1
        )

    flagged_count = sum(
        alert["is_flagged"]
        for alert in alerts
    )

    print("\n" + "=" * 55)
    print("HYBRID IDS DETECTION REPORT")
    print("=" * 55)

    print(f"Records analyzed: {len(alerts)}")

    print(f"Flagged records: {flagged_count}")

    print("\nRisk-level distribution:")

    for level in ["HIGH", "MEDIUM", "LOW", "INFO"]:

        print(
            f"{level}: {risk_counts.get(level, 0)}"
        )

    print("\nDetection sources:")

    print(
        f"Signature alerts: {len(signatures)}"
    )

    print(
        f"Anomaly alerts: {len(anomalies)}"
    )

    print(
        f"Machine learning models: {len(models)}"
    )

    print(
        f"\nHybrid alerts saved: {OUTPUT_FILE.resolve()}"
    )

    print("=" * 55)

    return alerts


# --------------------------------------------------
# COMMAND LINE INTERFACE
# --------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Combine signature, anomaly and ML "
            "detection into hybrid risk scores."
        )
    )

    parser.parse_args()

    try:

        run_hybrid_detection()

    except (OSError, ValueError, KeyError) as error:

        parser.exit(
            status=1,
            message=f"\nHybrid detection failed: {error}\n"
        )


if __name__ == "__main__":
    main()