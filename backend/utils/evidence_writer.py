import json
from pathlib import Path


def save_evidence(evidence, output_path: str):
    """Save extracted forensic evidence as JSON."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(evidence, file, indent=4)

    return path