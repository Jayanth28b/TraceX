import json

from backend.core.ai_anomaly_detector import AnomalyDetector


def main():
    with open(
        "samples/ai_training_data.json",
        encoding="utf-8"
    ) as file:
        evidence = json.load(file)

    detector = AnomalyDetector(contamination=0.1)

    detector.fit(evidence)

    results = detector.predict(evidence)

    anomalies = [
        result for result in results
        if result["is_anomaly"]
    ]

    print(f"Total events: {len(results)}")
    print(f"Anomalies detected: {len(anomalies)}")

    print("\nDetected anomalies:")

    for result in anomalies[:10]:
        print(
            f"Destination: "
            f"{result['event']['destination_ip']} | "
            f"Port: "
            f"{result['event']['destination_port']} | "
            f"Score: "
            f"{result['anomaly_score']}"
        )


if __name__ == "__main__":
    main()