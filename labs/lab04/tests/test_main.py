"""Тести командного інтерфейсу (інтеграційні, без мережі)."""

import json
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client, main

CVE_ID = "CVE-2099-10001"


def forbid_fetch(monkeypatch):
    """Підміна, яка падає, якщо програма спробує звернутися до мережі."""
    fake = Mock(side_effect=AssertionError("мережевий запит не очікувався"))
    monkeypatch.setattr(api_client, "fetch_response", fake)
    return fake


def test_local_run_prints_report(monkeypatch, capsys, sample_path):
    fake = forbid_fetch(monkeypatch)
    code = main.main(["--cve", CVE_ID, "--input", str(sample_path)])
    out, err = capsys.readouterr()

    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["decision"] == "review"
    assert report["variant"] == 7
    assert report["observed"] == "HIGH"
    fake.assert_not_called()


def test_network_mode_uses_client(monkeypatch, capsys, sample_payload):
    fake = Mock(return_value=sample_payload)
    monkeypatch.setattr(api_client, "fetch_response", fake)
    code = main.main(["--cve", CVE_ID])
    out, _ = capsys.readouterr()

    assert code == 0
    assert json.loads(out)["decision"] == "review"
    fake.assert_called_once_with(CVE_ID)


def test_not_found_exit_zero(monkeypatch, capsys, tmp_path):
    forbid_fetch(monkeypatch)
    path = tmp_path / "empty.json"
    path.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
    code = main.main(["--cve", CVE_ID, "--input", str(path)])
    out, _ = capsys.readouterr()

    assert code == 0
    assert json.loads(out)["decision"] == "not_found"


def test_missing_file(monkeypatch, capsys, tmp_path):
    forbid_fetch(monkeypatch)
    code = main.main(["--cve", CVE_ID, "--input", str(tmp_path / "nope.json")])
    out, err = capsys.readouterr()

    assert code == 1
    assert out == ""
    assert "не вдалося прочитати файл" in err
    assert "Traceback" not in err


def test_invalid_json_file(monkeypatch, capsys, tmp_path):
    forbid_fetch(monkeypatch)
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    code = main.main(["--cve", CVE_ID, "--input", str(path)])
    out, err = capsys.readouterr()

    assert code == 1
    assert out == ""
    assert "некоректний JSON" in err


def test_data_error_exit_one(monkeypatch, capsys, sample_path):
    forbid_fetch(monkeypatch)
    code = main.main(["--cve", "CVE-2021-44228", "--input", str(sample_path)])
    out, err = capsys.readouterr()

    assert code == 1
    assert out == ""
    assert "некоректні дані" in err


@pytest.mark.parametrize(
    "cve", ["cve-2021-44228", "CVE-21-44228", "CVE-2021-123", "CVE-2021-44228x"]
)
def test_invalid_cve_format(monkeypatch, capsys, cve):
    forbid_fetch(monkeypatch)
    assert main.main(["--cve", cve]) == 2
    assert "Помилка" in capsys.readouterr().err


def test_missing_cve_argument(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main.main([])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("variant", [0, 16, True, "7", None])
def test_invalid_variant_number(monkeypatch, capsys, variant, sample_path):
    forbid_fetch(monkeypatch)
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)
    assert main.main(["--cve", CVE_ID, "--input", str(sample_path)]) == 2
    assert "VARIANT_NUMBER" in capsys.readouterr().err


def test_http_404_error(monkeypatch, capsys):
    monkeypatch.setenv("NVD_API_KEY", "fake-secret-key")
    response = Mock(spec=requests.Response)
    response.status_code = 404
    error = requests.exceptions.HTTPError("404 Not Found", response=response)
    monkeypatch.setattr(api_client, "fetch_response", Mock(side_effect=error))

    code = main.main(["--cve", CVE_ID])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert "404" in err
    assert "fake-secret-key" not in err


@pytest.mark.parametrize(
    "error, text",
    [
        (requests.exceptions.Timeout(), "час очікування"),
        (requests.exceptions.ConnectionError(), "з'єднатися"),
        (requests.exceptions.JSONDecodeError("x", "{", 1), "не є коректним JSON"),
        (api_client.UnexpectedStatusError(301), "301"),
    ],
)
def test_network_errors(monkeypatch, capsys, error, text):
    monkeypatch.setattr(api_client, "fetch_response", Mock(side_effect=error))
    code = main.main(["--cve", CVE_ID])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert text in err
