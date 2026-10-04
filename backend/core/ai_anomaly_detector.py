from sklearn.ensemble import IsolationForest

from backend.core.feature_engineering import build_network_features


class AnomalyDetector:
    """Detect unusual network events using Isolation Forest."""

    def __init__(self, contamination=0.1):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42
        )

    def fit(self, evidence: list[dict]):
        """Train the anomaly detector on network features."""

        features = build_network_features(evidence)
        self.model.fit(features)

    def predict(self, evidence: list[dict]) -> list[dict]:
        """Return anomaly predictions for network events."""

        features = build_network_features(evidence)

        predictions = self.model.predict(features)
        scores = self.model.decision_function(features)

        results = []

        for event, prediction, score in zip(
            evidence, predictions, scores
        ):
            results.append({
                "event": event,
                "is_anomaly": bool(prediction == -1),
                "anomaly_score": round(float(score), 4),
            })

        return results