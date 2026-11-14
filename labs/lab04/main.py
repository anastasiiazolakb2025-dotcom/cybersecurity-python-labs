"""Командний інтерфейс: перегляд запису CVE з NVD або з локального файла."""

import argparse
import json
import re
import sys
from pathlib import Path

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def load_response(path: str | Path) -> object:
    """Читає локальну відповідь NVD у форматі UTF-8 JSON."""
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def build_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        description="Перегляд запису CVE з NVD і звіт за правилом варіанта."
    )
    parser.add_argument(
        "--cve", required=True, help="ідентифікатор, напр. CVE-2021-44228"
    )
    parser.add_argument("--input", help="шлях до локальної JSON-відповіді NVD")
    return parser


def _error(message: str) -> None:
    """Виводить повідомлення про помилку у stderr."""
    print(f"Помилка: {message}", file=sys.stderr)


def _is_valid_variant(value: object) -> bool:
    """Перевіряє, що номер варіанта — ціле число 1–15, не bool."""
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 15


def _get_payload(cve_id: str, input_path: str | None) -> object:
    """Отримує відповідь із файла (якщо задано) або з NVD."""
    if input_path is not None:
        return load_response(input_path)
    return api_client.fetch_response(cve_id)


def main(argv: list[str] | None = None) -> int:
    """Запускає програму й повертає код завершення (0, 1 або 2)."""
    args = build_parser().parse_args(argv)

    if not _is_valid_variant(VARIANT_NUMBER):
        _error("VARIANT_NUMBER у shared/student.py має бути цілим числом від 1 до 15")
        return 2
    if not CVE_PATTERN.fullmatch(args.cve):
        _error("ідентифікатор має формат CVE-РРРР-NNNN (наприклад, CVE-2021-44228)")
        return 2

    try:
        payload = _get_payload(args.cve, args.input)
    except requests.exceptions.Timeout:
        _error("перевищено час очікування відповіді NVD")
        return 1
    except requests.exceptions.ConnectionError:
        _error("не вдалося з'єднатися з NVD")
        return 1
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "невідомий"
        _error(f"NVD повернув HTTP-помилку, статус {status}")
        return 1
    except api_client.UnexpectedStatusError as exc:
        _error(f"NVD повернув неочікуваний статус {exc.status_code}")
        return 1
    except requests.exceptions.JSONDecodeError:
        _error("відповідь NVD не є коректним JSON")
        return 1
    except requests.exceptions.RequestException:
        _error("не вдалося виконати запит до NVD")
        return 1
    except json.JSONDecodeError:
        _error(f"файл {args.input} містить некоректний JSON")
        return 1
    except UnicodeDecodeError:
        _error(f"файл {args.input} не є текстом у кодуванні UTF-8")
        return 1
    except OSError:
        _error(f"не вдалося прочитати файл {args.input}")
        return 1

    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        _error(f"некоректні дані відповіді: {exc}")
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
