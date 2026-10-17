# Лабораторна робота №2 — Варіант 7
**Тема:** Аналізатор журналів активності користувачів

## Запуск
python -m labs.lab02.main demo
python -m labs.lab02.main analyze --activity-log labs/lab02/data/data/data_v07/user_activity.csv --out-report labs/lab02/data/data/data_v07/off_hours_audit.json

## Параметри CLI
- `--activity-log` — шлях до CSV
- `--out-report` — шлях до JSON-звіту
- `--after-hours` — показувати тільки позаробочі події
- `--verbose` — DEBUG-логування