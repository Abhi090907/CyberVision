from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

LABELS = ["phishing_ui", "fake_login_form", "clickjacking_overlay"]

try:
    import tensorflow as tf
except Exception:  # pragma: no cover - fallback when tensorflow is unavailable
    tf = None


@dataclass
class LoadedModel:
    model: Any
    framework: str


def model_loader() -> LoadedModel:
    """
    Loads a lightweight TensorFlow model graph when TensorFlow is available.
    Falls back to a deterministic heuristic-backed mock model contract otherwise.
    """
    if tf is None:
        return LoadedModel(model=None, framework="heuristic")

    model = tf.keras.Sequential(
        [
            tf.keras.layers.Input(shape=(4,)),
            tf.keras.layers.Dense(8, activation="relu"),
            tf.keras.layers.Dense(len(LABELS), activation="sigmoid"),
        ]
    )
    model.compile(optimizer="adam", loss="binary_crossentropy")
    return LoadedModel(model=model, framework="tensorflow")


def inference(loaded_model: LoadedModel, features: list[float]) -> list[dict[str, float]]:
    vector = np.asarray(features, dtype=np.float32).reshape(1, 4)

    if loaded_model.framework == "tensorflow" and loaded_model.model is not None:
        scores = loaded_model.model.predict(vector, verbose=0)[0].tolist()
    else:
        # Deterministic heuristic scores as controlled simulation
        edge_density, box_density, alignment_error, overlay_score = features
        scores = [
            min(1.0, 0.45 + edge_density * 0.6 + alignment_error * 0.25),
            min(1.0, 0.35 + box_density * 0.8 + alignment_error * 0.2),
            min(1.0, 0.25 + overlay_score * 0.9 + edge_density * 0.2),
        ]

    return [{"type": label, "confidence": float(round(score, 4))} for label, score in zip(LABELS, scores)]
