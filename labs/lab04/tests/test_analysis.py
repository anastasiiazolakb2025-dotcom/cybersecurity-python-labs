"""Модульні тести перевірки даних і правила варіанта 7."""

import copy

import pytest

from labs.lab04 import analysis

CVE_ID = "CVE-2099-10001"
VARIANT = 7


def make_report(payload: dict) -> dict:
    """Допоміжна функція: перевірка відповіді та формування звіту."""
    record = analysis.extract_record(payload, CVE_ID)
    return analysis.build_report(record, CVE_ID, VARIANT)


def cvss_data(payload: dict, index: int = 0) -> dict:
    """Повертає cvssData оцінки з указаним індексом."""
    return payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][index][
        "cvssData"
    ]


def test_sample_full_report(sample_payload):
    assert make_report(sample_payload) == {
        "cve_id": "CVE-2099-10001",
        "variant": 7,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {
            "threshold": 7.0,
            "field": "availabilityImpact",
            "expected": "HIGH",
        },
        "observed": "HIGH",
        "decision": "review",
    }


@pytest.mark.parametrize(
    "score, expected",
    [(6.9, "other"), (7.0, "review"), (7.1, "review"), (10, "review")],
)
def test_threshold_boundary(sample_payload, score, expected):
    cvss_data(sample_payload)["baseScore"] = score
    assert make_report(sample_payload)["decision"] == expected


@pytest.mark.parametrize("value", ["LOW", "NONE"])
def test_high_score_but_other_impact(sample_payload, value):
    cvss_data(sample_payload)["availabilityImpact"] = value
    report = make_report(sample_payload)
    assert report["decision"] == "other"
    assert report["observed"] == value


def test_not_found_all_data_null(sample_payload):
    sample_payload["vulnerabilities"] = []
    record = analysis.extract_record(sample_payload, CVE_ID)
    assert record is None
    report = analysis.build_report(record, CVE_ID, VARIANT)
    assert report["decision"] == "not_found"
    assert report["cve_id"] == CVE_ID
    assert report["variant"] == 7
    assert report["rule"] == {
        "threshold": 7.0,
        "field": "availabilityImpact",
        "expected": "HIGH",
    }
    for key in (
        "description",
        "vuln_status",
        "cvss_version",
        "score",
        "score_source",
        "vector",
        "observed",
    ):
        assert report[key] is None


def test_rejected_ignores_high_score(sample_payload):
    sample_payload["vulnerabilities"][0]["cve"]["vulnStatus"] = "Rejected"
    report = make_report(sample_payload)
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for offline API testing."
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_status_is_insufficient(sample_payload):
    del sample_payload["vulnerabilities"][0]["cve"]["vulnStatus"]
    report = make_report(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["score"] is None


def test_missing_metrics_is_insufficient(sample_payload):
    del sample_payload["vulnerabilities"][0]["cve"]["metrics"]
    report = make_report(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None


def test_empty_v31_list_is_insufficient(sample_payload):
    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = []
    assert make_report(sample_payload)["decision"] == "insufficient_data"


def test_missing_variant_field_is_insufficient(sample_payload):
    del cvss_data(sample_payload)["availabilityImpact"]
    report = make_report(sample_payload)
    assert report["decision"] == "insufficient_data"
    assert report["observed"] is None


@pytest.mark.parametrize("value", [None, "VERY_HIGH", "high", 3])
def test_invalid_variant_field_raises(sample_payload, value):
    cvss_data(sample_payload)["availabilityImpact"] = value
    with pytest.raises(ValueError):
        make_report(sample_payload)


@pytest.mark.parametrize(
    "score", ["9.8", True, None, float("nan"), float("inf"), -0.1, 10.1]
)
def test_invalid_score_raises(sample_payload, score):
    cvss_data(sample_payload)["baseScore"] = score
    with pytest.raises(ValueError):
        make_report(sample_payload)


@pytest.mark.parametrize("metrics", [None, [], "x"])
def test_metrics_wrong_type_raises(sample_payload, metrics):
    sample_payload["vulnerabilities"][0]["cve"]["metrics"] = metrics
    with pytest.raises(ValueError):
        make_report(sample_payload)


@pytest.mark.parametrize("value", [None, {}, "x"])
def test_cvss_list_wrong_type_raises(sample_payload, value):
    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = value
    with pytest.raises(ValueError):
        make_report(sample_payload)


def test_primary_has_priority_over_earlier_secondary(sample_payload):
    metrics = sample_payload["vulnerabilities"][0]["cve"]["metrics"]
    primary = metrics["cvssMetricV31"][0]
    secondary = copy.deepcopy(primary)
    secondary["source"] = "secondary@example.invalid"
    secondary["type"] = "Secondary"
    secondary["cvssData"]["baseScore"] = 5.0
    secondary["cvssData"]["availabilityImpact"] = "LOW"
    metrics["cvssMetricV31"] = [secondary, primary]

    report = make_report(sample_payload)
    assert report["score_source"] == "nvd@nist.gov"
    assert report["score"] == 9.8
    assert report["decision"] == "review"


def test_without_primary_first_is_selected(sample_payload):
    metrics = sample_payload["vulnerabilities"][0]["cve"]["metrics"]
    first = metrics["cvssMetricV31"][0]
    first["type"] = "Secondary"
    first["source"] = "first@example.invalid"
    second = copy.deepcopy(first)
    second["source"] = "second@example.invalid"
    second["cvssData"]["baseScore"] = 3.0
    metrics["cvssMetricV31"] = [first, second]

    report = make_report(sample_payload)
    assert report["score_source"] == "first@example.invalid"
    assert report["decision"] == "review"


def test_wrong_cve_id_raises(sample_payload):
    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, "CVE-2021-44228")


def test_two_vulnerabilities_raise(sample_payload):
    item = sample_payload["vulnerabilities"][0]
    sample_payload["vulnerabilities"].append(copy.deepcopy(item))
    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, CVE_ID)


@pytest.mark.parametrize("payload", [None, [], "text", {"vulnerabilities": None}])
def test_bad_payload_structure_raises(payload):
    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


def test_wrong_version_raises(sample_payload):
    cvss_data(sample_payload)["version"] = "3.0"
    with pytest.raises(ValueError):
        make_report(sample_payload)


def test_missing_optional_fields_become_none(sample_payload):
    metric = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    del metric["source"]
    del metric["cvssData"]["version"]
    del metric["cvssData"]["vectorString"]
    report = make_report(sample_payload)
    assert report["score_source"] is None
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["decision"] == "review"


def test_description_first_nonempty_english(sample_payload):
    sample_payload["vulnerabilities"][0]["cve"]["descriptions"] = [
        {"lang": "es", "value": "Descripción"},
        {"lang": "en", "value": "   "},
        {"lang": "en", "value": "English text"},
    ]
    assert make_report(sample_payload)["description"] == "English text"


def test_extract_does_not_modify_payload(sample_payload):
    original = copy.deepcopy(sample_payload)
    make_report(sample_payload)
    assert sample_payload == original


@pytest.mark.parametrize("variant", [0, 16, True, "7", 7.0])
def test_invalid_variant_raises(sample_payload, variant):
    record = analysis.extract_record(sample_payload, CVE_ID)
    with pytest.raises(ValueError):
        analysis.build_report(record, CVE_ID, variant)


@pytest.mark.parametrize("status", ["", "   ", None, 5])
def test_invalid_status_raises(sample_payload, status):
    sample_payload["vulnerabilities"][0]["cve"]["vulnStatus"] = status
    with pytest.raises(ValueError):
        make_report(sample_payload)


@pytest.mark.parametrize("item", [None, "x", {}, {"cve": None}, {"cve": []}])
def test_bad_vulnerability_item_raises(sample_payload, item):
    sample_payload["vulnerabilities"] = [item]
    with pytest.raises(ValueError):
        analysis.extract_record(sample_payload, CVE_ID)


@pytest.mark.parametrize("source", ["", None, 1])
def test_invalid_source_raises(sample_payload, source):
    metric = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    metric["source"] = source
    with pytest.raises(ValueError):
        make_report(sample_payload)


@pytest.mark.parametrize(
    "descriptions",
    [None, "text", [None], [{"lang": "en"}], [{"lang": 1, "value": "x"}]],
)
def test_bad_descriptions_raise(sample_payload, descriptions):
    sample_payload["vulnerabilities"][0]["cve"]["descriptions"] = descriptions
    with pytest.raises(ValueError):
        make_report(sample_payload)


def test_missing_cvss_data_raises(sample_payload):
    metric = sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]
    del metric["cvssData"]
    with pytest.raises(ValueError):
        make_report(sample_payload)


def test_non_dict_metric_item_raises(sample_payload):
    sample_payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"] = [None]
    with pytest.raises(ValueError):
        make_report(sample_payload)
