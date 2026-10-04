import os
import sys
import threading
import time
import webbrowser
from pathlib import Path


# Configure Streamlit before importing it.
os.environ["STREAMLIT_GLOBAL_DEVELOPMENTMODE"] = "false"
os.environ["STREAMLIT_SERVER_PORT"] = "8501"
os.environ["STREAMLIT_SERVER_ADDRESS"] = "localhost"
os.environ["STREAMLIT_SERVER_HEADLESS"] = "true"
os.environ["STREAMLIT_BROWSER_GATHERUSAGESTATS"] = "false"


from streamlit.web import bootstrap


def open_browser():
    """Open the TraceX dashboard in the default browser."""

    time.sleep(2)

    webbrowser.open(
        "http://localhost:8501"
    )


def main():
    """Launch the TraceX Streamlit dashboard."""

    if getattr(sys, "frozen", False):
        base_path = Path(sys._MEIPASS)
    else:
        base_path = Path(__file__).resolve().parent

    dashboard_path = (
        base_path
        / "backend"
        / "dashboard.py"
    )

    browser_thread = threading.Thread(
        target=open_browser,
        daemon=True,
    )

    browser_thread.start()

    bootstrap.run(
        str(dashboard_path),
        False,
        [],
        {},
    )


if __name__ == "__main__":
    main()