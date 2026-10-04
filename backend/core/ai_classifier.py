from sklearn.ensemble import RandomForestClassifier

from backend.core.feature_engineering import build_network_features


class ThreatClassifier:
    """Classify network events using a supervised ML model."""

    def __init__(self):
        self.model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            class_weight="balanced",
        )

    def fit(self, evidence: list[dict], labels: list[int]):
        """Train the classifier using labeled network evidence."""

        features = build_network_features(evidence)

        self.model.fit(features, labels)

    def predict(self, evidence: list[dict]) -> list[dict]:
        """Classify network events and return threat probabilities."""

        features = build_network_features(evidence)

        predictions = self.model.predict(features)
        probabilities = self.model.predict_proba(features)[:, 1]

        results = []

        for event, prediction, probability in zip(
            evidence,
            predictions,
            probabilities,
        ):
            results.append({
                "event": event,
                "is_threat": bool(prediction == 1),
                "threat_probability": round(
                    float(probability),
                    4,
                ),
            })

        return results