import importlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def guard(tmp_path, monkeypatch):
    """Свежий guard с данными во временной папке (карантин, база хэшей, конфиг)."""
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "appdata"))
    import guard as g
    return importlib.reload(g)
