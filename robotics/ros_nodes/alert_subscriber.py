#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import rospy
from std_msgs.msg import String

from robot_controller import RobotController


logger = logging.getLogger("robotics.alert_subscriber")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


def _normalize_alert(raw: dict[str, Any]) -> dict[str, str]:
    return {
        "type": str(raw.get("type", "unknown")),
        "severity": str(raw.get("severity", "Low")),
        "source": str(raw.get("source", "unknown")),
        "message": str(raw.get("message", "")),
        "timestamp": str(raw.get("timestamp", datetime.now(timezone.utc).isoformat())),
    }


class AlertSubscriberNode:
    def __init__(self) -> None:
        self.controller = RobotController()
        rospy.init_node("security_alert_subscriber", anonymous=False)
        self.subscriber = rospy.Subscriber("/security_alerts", String, self._on_alert, queue_size=50)
        logger.info("Subscribed to /security_alerts")

    def _on_alert(self, msg: String) -> None:
        try:
            payload = json.loads(msg.data)
            alert = _normalize_alert(payload)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.error("Invalid alert payload: %s | error=%s", msg.data, exc)
            return

        logger.info("Alert received: %s", json.dumps(alert))
        response = self.controller.react_to_alert(alert)
        logger.info("Robot response: %s", json.dumps(response))

    def spin(self) -> None:
        rospy.loginfo("AlertSubscriberNode started. Waiting for alerts...")
        rospy.spin()


if __name__ == "__main__":
    node = AlertSubscriberNode()
    node.spin()
