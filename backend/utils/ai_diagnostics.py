import json
import numpy as np

from backend.core.ai_anomaly_detector import AnomalyDetector
from backend.core.feature_engineering import build_network_features


def main():
    with open(
        "samples/ai_training_data.json",
        encoding="utf-8"
    ) as file:
        evidence = json.load(file)

    training_data = evidence[:80]
    test_normal = evidence[80:100]
    test_anomalous = evidence[100:]

    detector = AnomalyDetector(contamination=0.1)
    detector.fit(training_data)

    training_scores = detector.model.decision_function(
        build_network_features(training_data)
    )

    normal_scores = detector.model.decision_function(
        build_network_features(test_normal)
    )

    anomalous_scores = detector.model.decision_function(
        build_network_features(test_anomalous)
    )

    print("\nTRAINING SCORE RANGE")
    print(f"Min: {np.min(training_scores):.4f}")
    print(f"Max: {np.max(training_scores):.4f}")
    print(f"Mean: {np.mean(training_scores):.4f}")

    print("\nUNSEEN NORMAL SCORE RANGE")
    print(f"Min: {np.min(normal_scores):.4f}")
    print(f"Max: {np.max(normal_scores):.4f}")
    print(f"Mean: {np.mean(normal_scores):.4f}")

    print("\nANOMALOUS SCORE RANGE")
    print(f"Min: {np.min(anomalous_scores):.4f}")
    print(f"Max: {np.max(anomalous_scores):.4f}")
    print(f"Mean: {np.mean(anomalous_scores):.4f}")


if __name__ == "__main__":
    main()