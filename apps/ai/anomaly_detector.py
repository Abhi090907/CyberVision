from __future__ import annotations

from typing import Any

import cv2
import numpy as np


def _intersection_over_union(box_a: tuple[int, int, int, int], box_b: tuple[int, int, int, int]) -> float:
    ax, ay, aw, ah = box_a
    bx, by, bw, bh = box_b
    x_left = max(ax, bx)
    y_top = max(ay, by)
    x_right = min(ax + aw, bx + bw)
    y_bottom = min(ay + ah, by + bh)
    if x_right <= x_left or y_bottom <= y_top:
        return 0.0
    inter_area = float((x_right - x_left) * (y_bottom - y_top))
    a_area = float(aw * ah)
    b_area = float(bw * bh)
    union = a_area + b_area - inter_area
    return inter_area / union if union > 0 else 0.0


def detect_layout_anomalies(image: np.ndarray, edges: np.ndarray) -> list[dict[str, Any]]:
    height, width = image.shape[:2]
    page_area = float(height * width)
    contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    raw_boxes: list[tuple[int, int, int, int]] = []
    for contour in contours:
        x, y, w, h = cv2.boundingRect(contour)
        area = w * h
        if area < 300:
            continue
        raw_boxes.append((x, y, w, h))

    detections: list[dict[str, Any]] = []

    for x, y, w, h in raw_boxes:
        area_ratio = (w * h) / page_area
        aspect = w / max(h, 1)
        if area_ratio > 0.30:
            detections.append(
                {
                    "type": "clickjacking_overlay",
                    "confidence": round(min(0.99, 0.65 + area_ratio), 4),
                    "bbox": [int(x), int(y), int(w), int(h)],
                }
            )
        elif aspect > 8.0 or aspect < 0.2:
            detections.append(
                {
                    "type": "phishing_ui",
                    "confidence": round(min(0.95, 0.55 + min(abs(aspect - 1.0), 8.0) / 12.0), 4),
                    "bbox": [int(x), int(y), int(w), int(h)],
                }
            )

    for idx, box_a in enumerate(raw_boxes):
        for jdx in range(idx + 1, len(raw_boxes)):
            box_b = raw_boxes[jdx]
            iou = _intersection_over_union(box_a, box_b)
            if iou >= 0.35:
                x, y, w, h = box_a
                detections.append(
                    {
                        "type": "clickjacking_overlay",
                        "confidence": round(min(0.95, 0.60 + iou), 4),
                        "bbox": [int(x), int(y), int(w), int(h)],
                    }
                )

    return detections


def detect_alignment_inconsistencies(edges: np.ndarray) -> list[dict[str, Any]]:
    lines = cv2.HoughLinesP(
        edges,
        rho=1,
        theta=np.pi / 180,
        threshold=60,
        minLineLength=80,
        maxLineGap=10,
    )
    if lines is None or len(lines) < 3:
        return []

    horizontal_y: list[float] = []
    vertical_x: list[float] = []
    for line in lines:
        x1, y1, x2, y2 = line[0]
        dx = abs(x2 - x1)
        dy = abs(y2 - y1)
        if dx > dy * 2:
            horizontal_y.append((y1 + y2) / 2.0)
        elif dy > dx * 2:
            vertical_x.append((x1 + x2) / 2.0)

    detections: list[dict[str, Any]] = []
    if len(horizontal_y) >= 3:
        h_std = float(np.std(horizontal_y))
        if h_std > 80.0:
            detections.append(
                {
                    "type": "fake_login_form",
                    "confidence": round(min(0.9, 0.45 + h_std / 250.0), 4),
                    "bbox": [0, 0, int(edges.shape[1]), int(edges.shape[0])],
                }
            )
    if len(vertical_x) >= 3:
        v_std = float(np.std(vertical_x))
        if v_std > 120.0:
            detections.append(
                {
                    "type": "phishing_ui",
                    "confidence": round(min(0.9, 0.42 + v_std / 300.0), 4),
                    "bbox": [0, 0, int(edges.shape[1]), int(edges.shape[0])],
                }
            )
    return detections
