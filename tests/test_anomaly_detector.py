
"""
Tests for the Network IDS statistical anomaly detector.
"""

import csv

import pytest

from ids.anomaly_detector import (
    calculate_baseline,
    calculate_z_score,
    detect_anomalies,
    load_dataset,
    run_anomaly_detection,
)


FEATURES = [
    "bytes_per_second",
    "packets_per_second",
    "failed_connection_rate",
    "syn_ratio",
    "rst_ratio",
]


def make_record(index, outlier=False):
    """Create one synthetic record for anomaly testing."""

    record = {
        "flow_id": f"TEST-FLOW-{index:03d}",
        "timestamp": f"2026-10-03T10:{index:02d}:00",
        "source_ip": "192.0.2.10",
        "destination_ip": "203.0.113.10",
        "label": "NORMAL",
        "scenario_type": "NORMAL_WEB",
    }

    for feature in FEATURES:
        record[feature] = 1000.0 if outlier else 10.0

    return record


def write_dataset(path, records, fieldnames=None):
    """Write synthetic records to a CSV file."""

    if fieldnames is None:
        fieldnames = [
            "flow_id",
            "timestamp",
            "source_ip",
            "destination_ip",
            "label",
            "scenario_type",
            *FEATURES,
        ]

    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )
        writer.writeheader()

        for record in records:
            filtered_record = {
                field: record[field]
                for field in fieldnames
                if field in record
            }
            writer.writerow(filtered_record)


def test_load_dataset_reads_valid_records(tmp_path):
    path = tmp_path / "valid.csv"
    write_dataset(path, [make_record(index) for index in range(10)])

    records = load_dataset(path)

    assert len(records) == 10


def test_load_dataset_rejects_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_dataset(tmp_path / "missing.csv")


def test_load_dataset_rejects_dataset_with_too_few_rows(tmp_path):
    path = tmp_path / "small.csv"
    write_dataset(path, [make_record(index) for index in range(9)])

    with pytest.raises(ValueError):
        load_dataset(path)


def test_load_dataset_rejects_missing_required_column(tmp_path):
    path = tmp_path / "missing_column.csv"
    records = [make_record(index) for index in range(10)]

    fieldnames = [
        "flow_id",
        "timestamp",
        "source_ip",
        "destination_ip",
        "label",
        "scenario_type",
        *FEATURES[:-1],
    ]

    write_dataset(path, records, fieldnames)

    with pytest.raises(ValueError):
        load_dataset(path)


def test_load_dataset_rejects_non_numeric_feature(tmp_path):
    path = tmp_path / "invalid_feature.csv"
    records = [make_record(index) for index in range(10)]
    records[0]["bytes_per_second"] = "not-a-number"

    write_dataset(path, records)

    with pytest.raises(ValueError):
        load_dataset(path)


def test_load_dataset_rejects_infinite_feature_value(tmp_path):
    path = tmp_path / "infinite_feature.csv"
    records = [make_record(index) for index in range(10)]
    records[0]["bytes_per_second"] = "inf"

    write_dataset(path, records)

    with pytest.raises(ValueError):
        load_dataset(path)


def test_calculate_baseline_returns_all_features():
    records = [make_record(index) for index in range(10)]

    baseline = calculate_baseline(records)

    assert set(baseline.keys()) == set(FEATURES)


def test_calculate_z_score_for_value_above_mean():
    score = calculate_z_score(15, 10, 2)

    assert score == 2.5


def test_calculate_z_score_for_value_below_mean():
    score = calculate_z_score(5, 10, 2)

    assert score == -2.5


def test_calculate_z_score_returns_zero_for_zero_standard_deviation():
    score = calculate_z_score(100, 10, 0)

    assert score == 0


def test_detect_anomalies_returns_no_alerts_for_constant_records():
    records = [make_record(index) for index in range(10)]
    baseline = calculate_baseline(records)

    alerts = detect_anomalies(
        records,
        baseline,
        threshold=2.5,
    )

    assert alerts == []


def test_detect_anomalies_identifies_extreme_outlier():
    records = [make_record(index) for index in range(19)]
    records.append(make_record(19, outlier=True))

    baseline = calculate_baseline(records)

    alerts = detect_anomalies(
        records,
        baseline,
        threshold=2.5,
    )

    assert len(alerts) >= 1
    assert any(
        alert["flow_id"] == "TEST-FLOW-019"
        for alert in alerts
    )


def test_detect_anomalies_respects_supplied_threshold():
    records = [make_record(index) for index in range(19)]
    records.append(make_record(19, outlier=True))

    baseline = calculate_baseline(records)

    alerts_at_lower_threshold = detect_anomalies(
        records,
        baseline,
        threshold=2.5,
    )

    alerts_at_higher_threshold = detect_anomalies(
        records,
        baseline,
        threshold=5.0,
    )

    assert len(alerts_at_lower_threshold) > 0
    assert alerts_at_higher_threshold == []


def test_run_anomaly_detection_rejects_non_positive_threshold(tmp_path):
    input_path = tmp_path / "input.csv"
    output_path = tmp_path / "alerts.csv"

    write_dataset(
        input_path,
        [make_record(index) for index in range(10)],
    )

    with pytest.raises(ValueError):
        run_anomaly_detection(
            input_path,
            output_path,
            threshold=0,
        )


def test_run_anomaly_detection_creates_output_file(tmp_path):
    input_path = tmp_path / "input.csv"
    output_path = tmp_path / "alerts.csv"

    records = [make_record(index) for index in range(19)]
    records.append(make_record(19, outlier=True))

    write_dataset(input_path, records)

    alerts, baseline = run_anomaly_detection(
        input_path,
        output_path,
        threshold=2.5,
    )

    assert isinstance(alerts, list)
    assert set(baseline.keys()) == set(FEATURES)
    assert output_path.exists()