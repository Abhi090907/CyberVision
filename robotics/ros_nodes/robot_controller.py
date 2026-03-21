#!/usr/bin/env python3
from __future__ import annotations

import json
import logging
from typing import Any


logger = logging.getLogger("robotics.robot_controller")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)


class RobotController:
    """
    Lightweight controller with print/log-based state transitions.
    Keeps behavior simple and safe for local simulation.
    """

    def __init__(self) -> None:
        self.state = "IDLE"

    def _set_state(self, new_state: str, details: dict[str, Any]) -> None:
        self.state = new_state
        logger.info("Robot state => %s | details=%s", self.state, json.dumps(details))

    def react_to_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        severity = str(alert.get("severity", "Low")).strip().lower()
        alert_type = str(alert.get("type", "unknown")).strip()
        source = str(alert.get("source", "unknown")).strip()

        if severity == "high":
            self._set_state(
                "ALERT_MOVE",
                {
                    "action": "simulate evasive movement",
                    "type": alert_type,
                    "source": source,
                },
            )
            return {
                "state": self.state,
                "action": "Robot enters ALERT mode and simulates movement.",
            }

        if severity == "medium":
            self._set_state(
                "WARN_MONITOR",
                {
                    "action": "increase monitoring",
                    "type": alert_type,
                    "source": source,
                },
            )
            return {
                "state": self.state,
                "action": "Robot remains active with warning-level monitoring.",
            }

        self._set_state(
            "IDLE",
            {
                "action": "stay idle",
                "type": alert_type,
                "source": source,
            },
        )
        return {
            "state": self.state,
            "action": "Robot remains idle and logs low-severity alert.",
        }
