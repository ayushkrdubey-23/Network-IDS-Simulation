
"""
Tests for the Network IDS feature extraction module.
"""

import csv

import pytest

from ids.feature_extractor import (
    DERIVED_COLUMNS,
    REQUIRED_COLUMNS,
    extract_features,
    process_dataset,
    validate_record,
)


def make_valid_record():
    """Return a valid synthetic network-flow record."""

    return {
        "flow_id": "TEST-FLOW-001",
        "timestamp": "2026-10-03T10:00:00",
        "source_ip": "192.0.2.10",
        "destination_ip": "203.0.113.10",
        "source_port": "51515",
        "destination_port": "443",
        "protocol": "TCP",
        "packet_count": "100",
        "byte_count": "10000",
        "duration_seconds": "10",
        "connection_count": "4",
        "failed_connection_count": "2",
        "syn_count": "20",
        "rst_count": "10",
        "average_packet_size": "100",
        "label": "SUSPICIOUS",
        "scenario_type": "HIGH_CONNECTION_RATE",
    }


def write_csv(path, records, fieldnames=None):
    """Write test records to a CSV file."""

    if fieldnames is None:
        fieldnames = REQUIRED_COLUMNS

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)


def test_valid_record_has_no_validation_errors():
    assert validate_record(make_valid_record()) == []


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("source_ip", "8.8.8.8"),
        ("destination_ip", "192.0.2.20"),
        ("source_ip", "not-an-ip"),
        ("destination_ip", "invalid-ip"),
        ("timestamp", "not-a-timestamp"),
        ("protocol", "FTP"),
        ("label", "UNKNOWN"),
        ("source_port", "70000"),
        ("destination_port", "0"),
        ("packet_count", "-1"),
        ("byte_count", "-100"),
        ("connection_count", "-1"),
        ("failed_connection_count", "5"),
        ("duration_seconds", "0"),
        ("average_packet_size", "-10"),
    ],
)
def test_invalid_record_values_are_rejected(field, invalid_value):
    record = make_valid_record()
    record[field] = invalid_value

    assert len(validate_record(record)) > 0


def test_blank_required_field_is_rejected():
    record = make_valid_record()
    record["source_ip"] = ""

    assert len(validate_record(record)) > 0


def test_feature_extraction_calculates_all_derived_features():
    features = extract_features(make_valid_record())

    assert features["bytes_per_second"] == 1000.0
    assert features["packets_per_second"] == 10.0
    assert features["failed_connection_rate"] == 0.5
    assert features["syn_ratio"] == 0.2
    assert features["rst_ratio"] == 0.1


def test_feature_extraction_returns_all_derived_columns():
    features = extract_features(make_valid_record())

    assert set(features.keys()) == set(DERIVED_COLUMNS)


def test_feature_extraction_handles_zero_connections():
    record = make_valid_record()
    record["connection_count"] = "0"
    record["failed_connection_count"] = "0"

    features = extract_features(record)

    assert features["failed_connection_rate"] == 0.0


def test_feature_extraction_handles_zero_syn_and_rst_counts():
    record = make_valid_record()
    record["syn_count"] = "0"
    record["rst_count"] = "0"

    features = extract_features(record)

    assert features["syn_ratio"] == 0.0
    assert features["rst_ratio"] == 0.0


def test_process_dataset_returns_valid_and_invalid_record_lists(tmp_path):
    input_path = tmp_path / "input.csv"
    output_path = tmp_path / "processed.csv"

    write_csv(input_path, [make_valid_record()])

    valid_records, invalid_records = process_dataset(
        input_path,
        output_path,
    )

    assert len(valid_records) == 1
    assert len(invalid_records) == 0
    assert output_path.exists()


def test_process_dataset_identifies_invalid_records(tmp_path):
    input_path = tmp_path / "input.csv"
    output_path = tmp_path / "processed.csv"

    valid_record = make_valid_record()

    invalid_record = make_valid_record()
    invalid_record["source_ip"] = "8.8.8.8"

    write_csv(
        input_path,
        [valid_record, invalid_record],
    )

    valid_records, invalid_records = process_dataset(
        input_path,
        output_path,
    )

    assert len(valid_records) == 1
    assert len(invalid_records) == 1


def test_processed_csv_contains_derived_feature_columns(tmp_path):
    input_path = tmp_path / "input.csv"
    output_path = tmp_path / "processed.csv"

    write_csv(input_path, [make_valid_record()])

    process_dataset(input_path, output_path)

    with output_path.open(
        "r",
        newline="",
        encoding="utf-8",
    ) as file:
        output_columns = csv.DictReader(file).fieldnames

    for column in DERIVED_COLUMNS:
        assert column in output_columns


def test_required_columns_are_defined():
    assert "flow_id" in REQUIRED_COLUMNS
    assert "source_ip" in REQUIRED_COLUMNS
    assert "destination_ip" in REQUIRED_COLUMNS
    assert "label" in REQUIRED_COLUMNS


def test_derived_columns_are_not_empty():
    assert len(DERIVED_COLUMNS) == 5