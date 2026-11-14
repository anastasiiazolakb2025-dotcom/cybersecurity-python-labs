"""Перевірка відповіді NVD і застосування правила варіанта."""

import math

# Допустимі значення полів cvssData (CVSS v3.1).
ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "attackVector": frozenset({"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": frozenset({"NONE", "LOW", "HIGH"}),
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "integrityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "availabilityImpact": frozenset({"NONE", "LOW", "HIGH"}),
}

# Правила варіантів: номер -> (поріг, поле, очікуване значення).
RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}


def _require(condition: bool, message: str) -> None:
    """Піднімає ValueError з повідомленням, якщо умова не виконується."""
    if not condition:
        raise ValueError(message)


def _optional_string(container: dict, key: str, where: str) -> str | None:
    """Повертає None, якщо ключа немає; інакше вимагає непорожній рядок."""
    if key not in container:
        return None
    value = container[key]
    _require(
        isinstance(value, str) and bool(value.strip()),
        f"{where}.{key} має бути непорожнім рядком",
    )
    return value


def _is_valid_score(value: object) -> bool:
    """Перевіряє, що value — скінченне число 0–10, але не bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(value) and 0 <= value <= 10


def _pick_description(cve: dict) -> str | None:
    """Повертає перший непорожній англійський опис або None."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    _require(isinstance(descriptions, list), "cve.descriptions має бути списком")
    for item in descriptions:
        _require(
            isinstance(item, dict)
            and isinstance(item.get("lang"), str)
            and isinstance(item.get("value"), str),
            "елемент descriptions має містити рядки lang і value",
        )
    for item in descriptions:
        if item["lang"] == "en" and item["value"].strip():
            return item["value"]
    return None


def _pick_metric(cve: dict) -> dict | None:
    """Вибирає оцінку CVSS v3.1: перша Primary, інакше перша у списку."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    _require(isinstance(metrics, dict), "cve.metrics має бути словником")
    if "cvssMetricV31" not in metrics:
        return None
    metric_list = metrics["cvssMetricV31"]
    _require(isinstance(metric_list, list), "metrics.cvssMetricV31 має бути списком")
    if not metric_list:
        return None
    if not all(isinstance(item, dict) for item in metric_list):
        raise ValueError("елементи cvssMetricV31 мають бути словниками")
    for item in metric_list:
        if item.get("type") == "Primary":
            return item
    return metric_list[0]


def extract_record(payload: object, cve_id: str) -> dict | None:
    """Перевіряє відповідь NVD і повертає внутрішній запис або None.

    None означає, що запис не знайдено (порожній vulnerabilities).
    Формат запису (словник):
        vuln_status  -- str або None (статус NVD);
        description  -- str або None (англійський опис);
        has_score    -- bool: чи знайдено оцінку CVSS v3.1;
        score        -- float/int або None (baseScore вибраної оцінки);
        score_source -- str або None (source вибраної оцінки);
        cvss_version -- "3.1" або None;
        vector       -- str або None (vectorString);
        cvss_data    -- копія словника cvssData вибраної оцінки або None.
    Для статусу Rejected або відсутнього статусу оцінки не аналізуються.
    Піднімає ValueError у разі порушення структури даних.
    """
    _require(isinstance(payload, dict), "відповідь має бути JSON-об'єктом")
    vulnerabilities = payload.get("vulnerabilities")
    _require(isinstance(vulnerabilities, list), "vulnerabilities має бути списком")
    if len(vulnerabilities) == 0:
        return None
    if len(vulnerabilities) > 1:
        raise ValueError("для одного cveId очікується не більше одного запису")

    item = vulnerabilities[0]
    _require(
        isinstance(item, dict) and isinstance(item.get("cve"), dict),
        "елемент vulnerabilities має містити словник cve",
    )
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise ValueError("cve.id не збігається із запитаним ідентифікатором")

    record = {
        "vuln_status": _optional_string(cve, "vulnStatus", "cve"),
        "description": _pick_description(cve),
        "has_score": False,
        "score": None,
        "score_source": None,
        "cvss_version": None,
        "vector": None,
        "cvss_data": None,
    }
    if record["vuln_status"] is None or record["vuln_status"] == "Rejected":
        return record

    metric = _pick_metric(cve)
    if metric is None:
        return record

    cvss_data = metric.get("cvssData")
    _require(isinstance(cvss_data, dict), "cvssData має бути словником")
    score = cvss_data.get("baseScore")
    if not _is_valid_score(score):
        raise ValueError("baseScore має бути скінченним числом від 0 до 10")
    version = _optional_string(cvss_data, "version", "cvssData")
    if version is not None and version != "3.1":
        raise ValueError('cvssData.version має дорівнювати "3.1"')

    record["has_score"] = True
    record["score"] = score
    record["score_source"] = _optional_string(metric, "source", "cvssMetricV31")
    record["cvss_version"] = version
    record["vector"] = _optional_string(cvss_data, "vectorString", "cvssData")
    record["cvss_data"] = dict(cvss_data)
    return record


def build_report(record: dict | None, cve_id: str, variant: int) -> dict:
    """Застосовує правило варіанта до запису й повертає словник звіту.

    Піднімає ValueError для неправильного номера варіанта або
    некоректного значення поля варіанта (null чи недопустиме значення).
    """
    _require(
        isinstance(variant, int) and not isinstance(variant, bool),
        "номер варіанта має бути цілим числом",
    )
    if variant not in RULES:
        raise ValueError("номер варіанта має бути від 1 до 15")
    threshold, field, expected = RULES[variant]

    report = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": None,
    }

    if record is None:
        report["decision"] = "not_found"
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]

    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report
    if record["vuln_status"] is None or not record["has_score"]:
        report["decision"] = "insufficient_data"
        return report

    report["cvss_version"] = record["cvss_version"]
    report["score"] = record["score"]
    report["score_source"] = record["score_source"]
    report["vector"] = record["vector"]

    cvss_data = record["cvss_data"]
    if field not in cvss_data:
        report["decision"] = "insufficient_data"
        return report
    observed = cvss_data[field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise ValueError(f"cvssData.{field} має недопустиме значення")

    report["observed"] = observed
    if record["score"] >= threshold and observed == expected:
        report["decision"] = "review"
    else:
        report["decision"] = "other"
    return report
