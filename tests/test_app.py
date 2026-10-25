"""
Test UI interactions and Streamlit app flow using Streamlit AppTest.
"""

import os
from streamlit.testing.v1 import AppTest

APP_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))

def test_app_initial_render():
    at = AppTest.from_file(APP_PATH, default_timeout=15).run()
    assert not at.exception
    # Verify elements present
    assert len(at.markdown) > 0


def test_app_step_simulation():
    at = AppTest.from_file(APP_PATH, default_timeout=15).run()
    assert not at.exception

    # Find the step event button
    step_btn = None
    for b in at.button:
        if "Step Event" in b.label:
            step_btn = b
            break

    assert step_btn is not None
    # Click step event
    step_btn.click().run()
    assert not at.exception
    # Ingested at least 1 event
    assert at.session_state.current_event_idx == 1
