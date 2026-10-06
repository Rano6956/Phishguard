"""Test de fumée de l'interface Streamlit (ignoré si streamlit n'est pas installé)."""
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest  # noqa: E402

APP = str(Path(__file__).resolve().parent.parent / "app.py")


def test_app_analyzes_a_sample():
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.selectbox(key="sample").set_value("phishing/banque.eml").run()
    at.button[0].click().run()
    assert not at.exception
    assert any("PHISHING PROBABLE" in m.value for m in at.markdown)


def test_app_warns_on_empty_input():
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.button[0].click().run()
    assert at.warning and not at.exception
