"""Offline detection smoke test.

This script never opens sockets, sends packets, or captures traffic. It feeds
synthetic packet metadata directly into the existing detection pipeline so
model/category behavior can be checked safely in an isolated environment.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from diodeshield.config import load_config
from diodeshield.db import Repository
from diodeshield.pipeline import DetectionPipeline
from diodeshield.schemas import TrafficEvent


def make_window(
    *,
    protocol: str,
    count: int,
    packet_len: int,
    src_ip: str,
    dst_ip: str,
    ttl_values: list[int] | None = None,
    metadata: dict[str, object] | None = None,
) -> list[TrafficEvent]:
    start = datetime.now(timezone.utc)
    return [
        TrafficEvent(
            timestamp=start + timedelta(milliseconds=index),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=40000 + (index % 4),
            dst_port=19001,
            protocol=protocol,
            packet_len=packet_len,
            ttl=(ttl_values[index % len(ttl_values)] if ttl_values else 64),
            metadata=metadata or {},
            data_source="offline_validation",
        )
        for index in range(count)
    ]


def main() -> None:
    # In-memory persistence keeps this validation isolated from live evidence.
    repository = Repository(":memory:")
    pipeline = DetectionPipeline(repository, load_config())

    cases = {
        "udp_burst": make_window(
            protocol="UDP",
            count=300,
            packet_len=1200,
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
        ),
        "spoofing_indicator": make_window(
            protocol="UDP",
            count=8,
            packet_len=180,
            src_ip="192.0.2.11",
            dst_ip="198.51.100.21",
            metadata={"observed_socket_src_ip": "192.0.2.99"},
        ),
    }

    for name, events in cases.items():
        result = pipeline.process_window(events)
        if result is None:
            print(f"{name}: no persisted alert (review model/risk thresholds)")
            continue
        print(
            f"{name}: category={result['attack_category']} "
            f"severity={result['risk_level']} score={result['risk_score']:.3f} "
            f"models={result['model_scores']}"
        )


if __name__ == "__main__":
    main()
