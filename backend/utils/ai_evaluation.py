import json

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
)

from backend.core.ai_anomaly_detector import AnomalyDetector


def main():
    with open(
        "samples/ai_training_data.json",
        encoding="utf-8"
    ) as file:
        evidence = json.load(file)

    normal_events = evidence[:100]
    anomalous_events = evidence[100:]

    # Training uses only normal traffic.
    training_data = normal_events[:80]

    # Testing uses unseen normal + anomalous traffic.
    test_data = normal_events[80:] + anomalous_events

    actual = [0] * 20 + [1] * 10

    detector = AnomalyDetector(contamination=0.1)

    detector.fit(training_data)

    results = detector.predict(test_data)

    predicted = [
        1 if result["is_anomaly"] else 0
        for result in results
    ]

    print("\nTraining events:", len(training_data))
    print("Testing events:", len(test_data))

    print("\nConfusion Matrix:")
    print(confusion_matrix(actual, predicted))

    print("\nClassification Report:")
    print(
        classification_report(
            actual,
            predicted,
            target_names=["Normal", "Anomalous"],
            zero_division=0,
        )
    )


if __name__ == "__main__":
    main()