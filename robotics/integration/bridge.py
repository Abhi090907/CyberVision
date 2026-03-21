#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import rospy
from std_msgs.msg import String


logger = logging.getLogger("robotics.integration.bridge")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


def _build_alert(alert_data: dict[str, Any]) -> dict[str, str]:
    return {
        "type": str(alert_data.get("type", "vulnerability")),
        "severity": str(alert_data.get("severity", "Low")),
        "source": str(alert_data.get("source", "scanner")),
        "message": str(alert_data.get("message", "")),
        "timestamp": str(alert_data.get("timestamp", datetime.now(timezone.utc).isoformat())),
    }


def send_alert_to_ros(alert_data: dict[str, Any]) -> dict[str, str]:
    """
    Publishes a structured alert payload to /security_alerts.
    Can be called from Django/backend integration later.
    """
    alert = _build_alert(alert_data)
    payload = json.dumps(alert, ensure_ascii=True)

    node_name = "backend_security_bridge"
    if not rospy.core.is_initialized():
        rospy.init_node(node_name, anonymous=True, disable_signals=True)

    publisher = rospy.Publisher("/security_alerts", String, queue_size=10, latch=False)
    rospy.sleep(0.3)
    publisher.publish(String(data=payload))
    logger.info("Published alert to ROS topic /security_alerts: %s", payload)
    return alert
