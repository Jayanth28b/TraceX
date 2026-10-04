import json
from pathlib import Path


def save_investigation_report(report: dict, output_path: str):
    """Save the complete TraceX investigation report as JSON."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False,
        )

    return path