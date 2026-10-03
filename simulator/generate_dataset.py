
"""
Network Intrusion Detection System (IDS) Simulation
Synthetic Network Traffic Dataset Generator

Author: Ayush Kumar Dubey

Purpose:
Generate safe synthetic network-flow records for defensive
cybersecurity education and IDS testing.

No real network packets are transmitted.
"""

import argparse
import csv
import random
import ipaddress
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

RANDOM_SEED = 42

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = BASE_DIR / "data" / "network_traffic.csv"

FIELDNAMES = [
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

# Documentation-reserved address ranges.
SOURCE_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
]

DESTINATION_NETWORK = ipaddress.ip_network(
    "203.0.113.0/24"
)

SCENARIO_WEIGHTS = {
    "NORMAL_WEB": 25,
    "NORMAL_DNS": 10,
    "NORMAL_SSH": 8,
    "NORMAL_EMAIL": 7,
    "NORMAL_DATABASE": 5,
    "HIGH_CONNECTION_RATE": 10,
    "REPEATED_FAILED_CONNECTIONS": 10,
    "MULTI_PORT_PROBING_PATTERN": 8,
    "SYN_HEAVY_PATTERN": 7,
    "UNUSUAL_PORT_ACTIVITY": 5,
    "HIGH_TRAFFIC_VOLUME": 5,
}


# --------------------------------------------------
# IP GENERATION
# --------------------------------------------------

def generate_source_ip():
    """Generate an IP from a documentation-reserved range."""

    network = random.choice(SOURCE_NETWORKS)

    host_number = random.randint(10, 250)

    return str(
        network.network_address + host_number
    )


def generate_destination_ip():
    """Generate a documentation-reserved destination IP."""

    host_number = random.randint(10, 250)

    return str(
        DESTINATION_NETWORK.network_address + host_number
    )


# --------------------------------------------------
# TIMESTAMP GENERATION
# --------------------------------------------------

def generate_timestamp(start_time):
    """Generate a synthetic timestamp."""

    seconds = random.randint(0, 7 * 24 * 60 * 60)

    timestamp = start_time + timedelta(seconds=seconds)

    return timestamp.isoformat()


# --------------------------------------------------
# NORMAL TRAFFIC GENERATION
# --------------------------------------------------

def generate_normal_flow(scenario, flow_id, start_time):

    services = {
        "NORMAL_WEB": (443, "TCP"),
        "NORMAL_DNS": (53, "UDP"),
        "NORMAL_SSH": (22, "TCP"),
        "NORMAL_EMAIL": (587, "TCP"),
        "NORMAL_DATABASE": (3306, "TCP"),
    }

    destination_port, protocol = services[scenario]

    packet_count = random.randint(5, 100)

    average_size = random.randint(300, 1400)

    byte_count = packet_count * average_size

    duration = round(
        random.uniform(0.5, 30.0), 3
    )

    connection_count = random.randint(1, 5)

    failed_count = random.randint(0, 1)

    syn_count = connection_count

    rst_count = random.randint(0, 1)

    return {
        "flow_id": flow_id,
        "timestamp": generate_timestamp(start_time),
        "source_ip": generate_source_ip(),
        "destination_ip": generate_destination_ip(),
        "source_port": random.randint(49152, 65535),
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": connection_count,
        "failed_connection_count": failed_count,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "average_packet_size": round(
            byte_count / packet_count, 2
        ),
        "label": "NORMAL",
        "scenario_type": scenario,
    }


# --------------------------------------------------
# SUSPICIOUS SYNTHETIC PATTERNS
# --------------------------------------------------

def generate_suspicious_flow(scenario, flow_id, start_time):

    source_ip = generate_source_ip()
    destination_ip = generate_destination_ip()

    # Default synthetic suspicious values.
    packet_count = random.randint(50, 200)
    byte_count = random.randint(20000, 100000)
    duration = round(random.uniform(0.2, 5.0), 3)

    connection_count = random.randint(10, 30)
    failed_count = 0
    syn_count = random.randint(10, 30)
    rst_count = random.randint(0, 5)

    destination_ports = {
        "HIGH_CONNECTION_RATE": 443,
        "REPEATED_FAILED_CONNECTIONS": 22,
        "MULTI_PORT_PROBING_PATTERN": random.randint(1000, 9000),
        "SYN_HEAVY_PATTERN": 443,
        "UNUSUAL_PORT_ACTIVITY": random.choice(
            [4444, 5555, 8081, 9001, 10000]
        ),
        "HIGH_TRAFFIC_VOLUME": 443,
    }

    destination_port = destination_ports[scenario]

    protocol = "TCP"

    if scenario == "HIGH_CONNECTION_RATE":

        connection_count = random.randint(80, 200)
        packet_count = random.randint(300, 700)
        syn_count = random.randint(70, 180)

    elif scenario == "REPEATED_FAILED_CONNECTIONS":

        connection_count = random.randint(20, 60)
        failed_count = random.randint(
            15, connection_count
        )
        rst_count = random.randint(10, failed_count)
        syn_count = connection_count

    elif scenario == "MULTI_PORT_PROBING_PATTERN":

        # Different generated records represent a source
        # contacting different destination ports.
        destination_port = random.randint(1, 65535)
        connection_count = random.randint(10, 25)
        failed_count = random.randint(5, 15)
        syn_count = connection_count

    elif scenario == "SYN_HEAVY_PATTERN":

        packet_count = random.randint(100, 300)
        connection_count = random.randint(20, 50)
        syn_count = random.randint(80, 200)
        rst_count = random.randint(5, 20)

    elif scenario == "UNUSUAL_PORT_ACTIVITY":

        destination_port = random.choice(
            [4444, 5555, 8081, 9001, 10000]
        )
        connection_count = random.randint(5, 20)

    elif scenario == "HIGH_TRAFFIC_VOLUME":

        packet_count = random.randint(5000, 15000)
        byte_count = random.randint(
            5000000, 20000000
        )
        duration = round(
            random.uniform(1.0, 10.0), 3
        )
        connection_count = random.randint(20, 50)

    # Keep packet statistics internally consistent.
    byte_count = max(byte_count, packet_count)

    return {
        "flow_id": flow_id,
        "timestamp": generate_timestamp(start_time),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": random.randint(49152, 65535),
        "destination_port": destination_port,
        "protocol": protocol,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": duration,
        "connection_count": connection_count,
        "failed_connection_count": failed_count,
        "syn_count": syn_count,
        "rst_count": rst_count,
        "average_packet_size": round(
            byte_count / packet_count, 2
        ),
        "label": "SUSPICIOUS",
        "scenario_type": scenario,
    }


# --------------------------------------------------
# DATASET GENERATION
# --------------------------------------------------

def generate_dataset(record_count=5000, output_path=None):

    if record_count < 1:
        raise ValueError(
            "Record count must be at least 1."
        )

    random.seed(RANDOM_SEED)

    if output_path is None:
        output_path = DEFAULT_OUTPUT

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    scenarios = list(SCENARIO_WEIGHTS.keys())

    weights = list(SCENARIO_WEIGHTS.values())

    start_time = datetime.now(
        timezone.utc
    ) - timedelta(days=7)

    records = []

    for index in range(1, record_count + 1):

        scenario = random.choices(
            scenarios,
            weights=weights,
            k=1
        )[0]

        flow_id = f"FLOW-{index:06d}"

        if scenario.startswith("NORMAL_"):

            record = generate_normal_flow(
                scenario,
                flow_id,
                start_time
            )

        else:

            record = generate_suspicious_flow(
                scenario,
                flow_id,
                start_time
            )

        records.append(record)

    # Save dataset as CSV.
    with output_path.open(
        "w",
        newline="",
        encoding="utf-8"
    ) as csv_file:

        writer = csv.DictWriter(
            csv_file,
            fieldnames=FIELDNAMES
        )

        writer.writeheader()

        writer.writerows(records)

    # Display generation summary.
    labels = Counter(
        record["label"] for record in records
    )

    scenario_counts = Counter(
        record["scenario_type"] for record in records
    )

    print("\n" + "=" * 55)
    print("NETWORK IDS - DATASET GENERATION COMPLETE")
    print("=" * 55)

    print(f"Total records: {len(records)}")

    print(f"Normal records: {labels['NORMAL']}")

    print(
        f"Suspicious records: {labels['SUSPICIOUS']}"
    )

    print("\nScenario distribution:")

    for scenario, count in sorted(
        scenario_counts.items()
    ):

        print(f"{scenario}: {count}")

    print("\nCSV columns:")

    print(", ".join(FIELDNAMES))

    print(f"\nSaved file: {output_path.resolve()}")

    print("=" * 55)

    return records


# --------------------------------------------------
# COMMAND LINE INTERFACE
# --------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Generate safe synthetic network-flow "
            "records for IDS simulation."
        )
    )

    parser.add_argument(
        "--records",
        type=int,
        default=5000,
        help="Number of records to generate."
    )

    parser.add_argument(
        "--output",
        type=str,
        default=str(DEFAULT_OUTPUT),
        help="Output CSV file path."
    )

    args = parser.parse_args()

    try:

        generate_dataset(
            record_count=args.records,
            output_path=args.output
        )

    except (ValueError, OSError) as error:

        parser.exit(
            status=1,
            message=f"\nDataset generation failed: {error}\n"
        )


if __name__ == "__main__":
    main()

