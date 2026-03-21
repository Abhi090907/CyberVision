from __future__ import annotations

from pathlib import Path
from typing import Any

import cv2
import numpy as np

from apps.ai.anomaly_detector import detect_alignment_inconsistencies, detect_layout_anomalies
from apps.ai.model_loader import inference, model_loader


def preprocess_image(image_path: str) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    image = cv2.imread(image_path)
    if image is None:
        raise RuntimeError(f"Unable to load screenshot image at {image_path}")
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    edges = cv2.Canny(gray, 70, 180)
    return image, gray, edges


def _extract_features(gray: np.ndarray, edges: np.ndarray, detections: list[dict[str, Any]]) -> list[float]:
    edge_density = float(np.count_nonzero(edges)) / float(edges.size)
    box_density = min(1.0, len(detections) / 20.0)
    centers = []
    overlay_score = 0.0
    for item in detections:
        x, y, w, h = item["bbox"]
        centers.append((x + w / 2.0, y + h / 2.0))
        if item["type"] == "clickjacking_overlay":
            overlay_score = max(overlay_score, min(1.0, (w * h) / (gray.shape[0] * gray.shape[1])))
    if len(centers) > 1:
        xs = [c[0] for c in centers]
        ys = [c[1] for c in centers]
        alignment_error = min(1.0, (float(np.std(xs)) + float(np.std(ys))) / 500.0)
    else:
        alignment_error = 0.1
    return [edge_density, box_density, alignment_error, overlay_score]


def _merge_detections(
    rule_detections: list[dict[str, Any]],
    model_predictions: list[dict[str, float]],
) -> list[dict[str, Any]]:
    merged = [dict(item) for item in rule_detections]
    if not merged:
        default_bbox = [0, 0, 1, 1]
        merged = [
            {
                "type": pred["type"],
                "confidence": round(max(0.2, pred["confidence"]), 4),
                "bbox": default_bbox,
            }
            for pred in model_predictions
            if pred["confidence"] >= 0.35
        ]
        return merged

    best_by_type: dict[str, float] = {item["type"]: item["confidence"] for item in merged}
    for pred in model_predictions:
        if pred["confidence"] < 0.35:
            continue
        if pred["type"] in best_by_type:
            continue
        merged.append(
            {
                "type": pred["type"],
                "confidence": round(pred["confidence"], 4),
                "bbox": merged[0]["bbox"],
            }
        )
    return merged


def annotate_image(image: np.ndarray, detections: list[dict[str, Any]], output_path: str) -> str:
    canvas = image.copy()
    for det in detections:
        x, y, w, h = [int(v) for v in det["bbox"]]
        cv2.rectangle(canvas, (x, y), (x + w, y + h), (0, 0, 255), 2)
        label = f"{det['type']} ({det['confidence']:.2f})"
        cv2.putText(
            canvas,
            label,
            (x, max(20, y - 8)),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.5,
            (0, 255, 255),
            1,
            cv2.LINE_AA,
        )
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    success = cv2.imwrite(output_path, canvas)
    if not success:
        raise RuntimeError(f"Failed to save annotated image to {output_path}")
    return output_path


def run_vision_pipeline(image_path: str, annotated_output_path: str) -> dict[str, Any]:
    image, gray, edges = preprocess_image(image_path)
    layout_detections = detect_layout_anomalies(image, edges)
    alignment_detections = detect_alignment_inconsistencies(edges)
    rule_detections = layout_detections + alignment_detections

    model = model_loader()
    features = _extract_features(gray, edges, rule_detections)
    predictions = inference(model, features)
    detections = _merge_detections(rule_detections, predictions)

    annotated_path = annotate_image(image, detections, annotated_output_path)
    return {
        "image_path": image_path,
        "annotated_image_path": annotated_path,
        "detections": detections,
    }
