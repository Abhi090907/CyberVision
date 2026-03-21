#!/usr/bin/env python3
from __future__ import annotations

import argparse

from integration.bridge import send_alert_to_ros


def main() -> int:
    parser = argparse.ArgumentParser(description="Send test security alert to ROS topic.")
    parser.add_argument("--type", default="vulnerability", help="Alert type")
    parser.add_argument("--severity", default="Medium", choices=["High", "Medium", "Low"], help="Severity")
    parser.add_argument("--source", default="scanner", choices=["scanner", "ai", "attack"], help="Source module")
    parser.add_argument("--message", default="Test alert from CLI", help="Alert message")
    args = parser.parse_args()

    payload = {
        "type": args.type,
        "severity": args.severity,
        "source": args.source,
        "message": args.message,
    }
    sent = send_alert_to_ros(payload)
    print(sent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
