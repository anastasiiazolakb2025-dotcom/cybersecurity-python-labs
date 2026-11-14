"""Спільні фікстури тестів ЛР №4."""

import copy
import json
from pathlib import Path

import pytest

SAMPLE_PATH = Path(__file__).resolve().parent.parent / "data" / "nvd_sample.json"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    """Забороняє справжні запити Requests і прибирає успадкований ключ."""
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_payload() -> dict:
    """Нова глибока копія синтетичної відповіді для кожного тесту."""
    with SAMPLE_PATH.open(encoding="utf-8") as file:
        return copy.deepcopy(json.load(file))


@pytest.fixture
def sample_path() -> Path:
    """Шлях до синтетичного файла відповіді."""
    return SAMPLE_PATH
