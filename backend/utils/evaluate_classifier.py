import json

from sklearn.metrics import (
    classification_report,
    confusion_matrix,
)

from backend.core.ai_classifier import ThreatClassifier


def main():
    with open(
        "samples/ai_training_data.json",
        encoding="utf-8"
    ) as file:
        evidence = json.load(file)

    normal_events = evidence[:100]
    anomalous_events = evidence[100:]

    # Training data
    training_data = (
        normal_events[:80]
        + anomalous_events
    )

    training_labels = (
        [0] * 80
        + [1] * 10
    )

    # Completely unseen test data
    test_data = normal_events[80:] + anomalous_events
    test_labels = [0] * 20 + [1] * 10

    classifier = ThreatClassifier()
    classifier.fit(training_data, training_labels)

    results = classifier.predict(test_data)

    predictions = [
        1 if result["is_threat"] else 0
        for result in results
    ]

    print("\nTraining events:", len(training_data))
    print("Testing events:", len(test_data))

    print("\nConfusion Matrix:")
    print(confusion_matrix(test_labels, predictions))

    print("\nClassification Report:")
    print(
        classification_report(
            test_labels,
            predictions,
            target_names=["Normal", "Threat"],
            zero_division=0,
        )
    )


if __name__ == "__main__":
    main()
    