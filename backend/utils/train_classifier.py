import json
from pathlib import Path

import joblib

from backend.core.ai_classifier import ThreatClassifier


DATASET_PATH = Path("samples/ai_training_data.json")
MODEL_PATH = Path("models/threat_classifier.joblib")


def main():
    """Train and save the TraceX threat classification model."""

    with DATASET_PATH.open("r", encoding="utf-8") as file:
        evidence = json.load(file)

    normal_events = evidence[:100]
    anomalous_events = evidence[100:]

    training_events = normal_events + anomalous_events
    training_labels = (
        [0] * len(normal_events)
        + [1] * len(anomalous_events)
    )

    classifier = ThreatClassifier()
    classifier.fit(
        training_events,
        training_labels,
    )

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(classifier.model, MODEL_PATH)

    print("[TraceX] Threat classifier trained.")
    print(f"[TraceX] Training events: {len(training_events)}")
    print(f"[TraceX] Model saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()