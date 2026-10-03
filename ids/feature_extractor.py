
"""
Network Intrusion Detection System (IDS) Simulation

Feature Extraction and Dataset Validation

Author: Ayush Kumar Dubey

This module validates synthetic network-flow records
and calculates additional features for IDS analysis.

No real network traffic is accessed.
"""

import argparse
import csv
import ipaddress
from collections import Counter
from datetime import datetime
from pathlib import Path


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

INPUT_FILE = BASE_DIR / "data" / "network_traffic.csv"

OUTPUT_FILE = (
    BASE_DIR / "data" / "processed_network_traffic.csv"
)

REQUIRED_COLUMNS = [
    "flow_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "packet_count",
    "byte_count",
    "duration_seconds",
    "connection_count",
    "failed_connection_count",
    "syn_count",
    "rst_count",
    "average_packet_size",
    "label",
    "scenario_type",
]

VALID_LABELS = {"NORMAL", "SUSPICIOUS"}
VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}

SOURCE_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
]

DESTINATION_NETWORK = ipaddress.ip_network(
    "203.0.113.0/24"
)


DERIVED_COLUMNS = [
    "bytes_per_second",
    "packets_per_second",
    "failed_connection_rate",
    "syn_ratio",
    "rst_ratio",
]


# --------------------------------------------------
# VALIDATION HELPERS
# --------------------------------------------------

def validate_ip_address(value, field_name):

    try:
        address = ipaddress.ip_address(value)

    except ValueError:
        raise ValueError(
            f"{field_name} contains an invalid IP address: {value}"
        )

    return address


def validate_record(record):

    errors = []

    # Check IP addresses.
    try:
        source_ip = validate_ip_address(
            record["source_ip"],
            "source_ip"
        )

        if not any(
            source_ip in network
            for network in SOURCE_NETWORKS
        ):
            errors.append(
                "source_ip is outside the configured documentation ranges"
            )

    except ValueError as error:
        errors.append(str(error))

    try:
        destination_ip = validate_ip_address(
            record["destination_ip"],
            "destination_ip"
        )

        if destination_ip not in DESTINATION_NETWORK:
            errors.append(
                "destination_ip is outside the configured documentation range"
            )

    except ValueError as error:
        errors.append(str(error))

    # Check timestamp.
    try:
        datetime.fromisoformat(record["timestamp"])

    except ValueError:
        errors.append("Invalid timestamp")

    # Check protocol.
    if record["protocol"] not in VALID_PROTOCOLS:
        errors.append("Unsupported protocol")

    # Check label.
    if record["label"] not in VALID_LABELS:
        errors.append("Invalid traffic label")

    # Validate integer fields.
    integer_fields = [
        "source_port",
        "destination_port",
        "packet_count",
        "byte_count",
        "connection_count",
        "failed_connection_count",
        "syn_count",
        "rst_count",
    ]

    integer_values = {}

    for field in integer_fields:

        try:
            value = int(record[field])
            integer_values[field] = value

        except (ValueError, TypeError):
            errors.append(
                f"{field} must be an integer"
            )

    # Validate numeric fields.
    try:
        duration = float(
            record["duration_seconds"]
        )

        if duration <= 0:
            errors.append(
                "duration_seconds must be greater than zero"
            )

    except (ValueError, TypeError):
        duration = None
        errors.append(
            "duration_seconds must be numeric"
        )

    try:
        average_size = float(
            record["average_packet_size"]
        )

        if average_size <= 0:
            errors.append(
                "average_packet_size must be greater than zero"
            )

    except (ValueError, TypeError):
        errors.append(
            "average_packet_size must be numeric"
        )

    # Check ranges if integer conversion succeeded.
    if len(integer_values) == len(integer_fields):

        if not 1 <= integer_values["source_port"] <= 65535:
            errors.append("Invalid source port")

        if not 1 <= integer_values["destination_port"] <= 65535:
            errors.append("Invalid destination port")

        for field in [
            "packet_count",
            "byte_count",
            "connection_count",
            "failed_connection_count",
            "syn_count",
            "rst_count",
        ]:

            if integer_values[field] < 0:
                errors.append(
                    f"{field} cannot be negative"
                )

        if integer_values["packet_count"] <= 0:
            errors.append(
                "packet_count must be greater than zero"
            )

        if (
            integer_values["failed_connection_count"]
            > integer_values["connection_count"]
        ):
            errors.append(
                "Failed connections cannot exceed total connections"
            )

    return errors


# --------------------------------------------------
# FEATURE EXTRACTION
# --------------------------------------------------

def extract_features(record):

    packet_count = int(record["packet_count"])
    byte_count = int(record["byte_count"])

    duration = float(
        record["duration_seconds"]
    )

    connection_count = int(
        record["connection_count"]
    )

    failed_count = int(
        record["failed_connection_count"]
    )

    syn_count = int(record["syn_count"])
    rst_count = int(record["rst_count"])

    # Avoid division by zero.
    safe_duration = max(duration, 0.001)
    safe_connections = max(connection_count, 1)
    safe_packets = max(packet_count, 1)

    return {
        "bytes_per_second": round(
            byte_count / safe_duration,
            2
        ),

        "packets_per_second": round(
            packet_count / safe_duration,
            2
        ),

        "failed_connection_rate": round(
            failed_count / safe_connections,
            4
        ),

        "syn_ratio": round(
            syn_count / safe_packets,
            4
        ),

        "rst_ratio": round(
            rst_count / safe_packets,
            4
        ),
    }


# --------------------------------------------------
# DATASET PROCESSING
# --------------------------------------------------

def process_dataset(input_path, output_path):

    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Input dataset not found: {input_path}"
        )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    valid_records = []
    invalid_records = []

    with input_path.open(
        "r",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        reader = csv.DictReader(csv_file)

        if reader.fieldnames is None:
            raise ValueError(
                "Input CSV is empty or has no header."
            )

        missing_columns = [
            column
            for column in REQUIRED_COLUMNS
            if column not in reader.fieldnames
        ]

        if missing_columns:
            raise ValueError(
                "Missing required columns: "
                + ", ".join(missing_columns)
            )

        for row_number, record in enumerate(
            reader,
            start=2
        ):

            errors = validate_record(record)

            if errors:

                invalid_records.append({
                    "row": row_number,
                    "errors": errors,
                })

                continue

            features = extract_features(record)

            processed_record = dict(record)

            processed_record.update(features)

            valid_records.append(
                processed_record
            )

    output_columns = (
        REQUIRED_COLUMNS + DERIVED_COLUMNS
    )

    with output_path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as output_csv:

        writer = csv.DictWriter(
            output_csv,
            fieldnames=output_columns
        )

        writer.writeheader()

        writer.writerows(valid_records)

    # Generate summary.
    label_counts = Counter(
        record["label"]
        for record in valid_records
    )

    print("\n" + "=" * 55)
    print("IDS FEATURE EXTRACTION REPORT")
    print("=" * 55)

    print(f"Input file: {input_path}")

    print(
        f"Total valid records: {len(valid_records)}"
    )

    print(
        f"Invalid records: {len(invalid_records)}"
    )

    print(
        f"Normal records: {label_counts['NORMAL']}"
    )

    print(
        f"Suspicious records: {label_counts['SUSPICIOUS']}"
    )

    print("\nExtracted features:")

    for feature in DERIVED_COLUMNS:
        print(f"- {feature}")

    print(
        f"\nProcessed dataset saved to: {output_path}"
    )

    if invalid_records:

        print("\nFirst five validation errors:")

        for item in invalid_records[:5]:

            print(
                f"Row {item['row']}: "
                + "; ".join(item["errors"])
            )

    print("=" * 55)

    return valid_records, invalid_records


# --------------------------------------------------
# COMMAND LINE INTERFACE
# --------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Validate synthetic network-flow data "
            "and extract IDS features."
        )
    )

    parser.add_argument(
        "--input",
        default=str(INPUT_FILE),
        help="Input CSV dataset path."
    )

    parser.add_argument(
        "--output",
        default=str(OUTPUT_FILE),
        help="Processed CSV output path."
    )

    args = parser.parse_args()

    try:

        process_dataset(
            input_path=args.input,
            output_path=args.output
        )

    except (OSError, ValueError) as error:

        parser.exit(
            status=1,
            message=f"\nProcessing failed: {error}\n"
        )


if __name__ == "__main__":
    main()