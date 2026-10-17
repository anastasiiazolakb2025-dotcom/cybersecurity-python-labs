import argparse
import csv
import json
import logging
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("activity_audit")

CRITICAL_PATTERN = re.compile(r"(hr_db|finance|confidential|nas|export)", re.IGNORECASE)


def is_off_hours(timestamp):
    if timestamp.weekday() >= 5:
        return True
    return timestamp.hour < 6 or timestamp.hour >= 22


def parse_time(time_str):
    time_str = time_str.strip()
    try:
        return datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.fromisoformat(time_str)


def main():
    parser = argparse.ArgumentParser(description="Аналізатор активності користувачів")
    parser.add_argument("--activity-log", required=True, type=Path, help="Шлях до CSV файлу")
    parser.add_argument("--out-report", type=Path, help="Шлях до JSON звіту")
    parser.add_argument("--after-hours", action="store_true", help="Показати тільки позаробочі події")
    parser.add_argument("--verbose", action="store_true", help="Увімкнути детальне логування")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="[%(levelname)s] %(message)s")

    if not args.activity_log.exists():
        logger.error("Файл не знайдено: %s", args.activity_log)
        sys.exit(2)

    logger.info("Читаємо файл %s...", args.activity_log)
    
    records = []

    with args.activity_log.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                records.append({
                    "time": parse_time(row["Timestamp"]),
                    "user": row["UserID"],
                    "action": row["Action"],
                    "resource": row["Resource"],
                    "ip": row["IP"],
                })
            except (ValueError, KeyError, TypeError) as e:
                logger.warning("Пропущено рядок: %s", e)

    logger.info("Оброблено записів: %d", len(records))

    off_hours_events = []
    user_stats = defaultdict(lambda: {"off_hours": 0, "critical": 0, "mass": 0})

    for r in records:
        if is_off_hours(r["time"]):
            off_hours_events.append(r)
            user_stats[r["user"]]["off_hours"] += 1

        if CRITICAL_PATTERN.search(r["resource"]):
            user_stats[r["user"]]["critical"] += 1

    user_times = defaultdict(list)
    for r in records:
        user_times[r["user"]].append(r["time"])

    for user, times in user_times.items():
        times.sort()
        for i in range(len(times)):
            count = 0
            for j in range(i, len(times)):
                if (times[j] - times[i]).total_seconds() <= 60:
                    count += 1
            if count >= 50:
                user_stats[user]["mass"] += 1
                break

    print("\n User Activity Audit")
    print(f"Всього записів: {len(records)}")
    
    print(f"\n Підозрілі події поза робочим часом ({len(off_hours_events)})")
    for r in off_hours_events[:10]:
        print(f"  [ALERT] {r['user']} | {r['time']} | {r['action']} {r['resource']}")

    print("\n Аномалії масових запитів")
    for user, stats in user_stats.items():
        if stats["mass"] > 0:
            print(f"  [ALERT] {user} зробив більше 50 запитів за хвилину!")

    if args.out_report:
        args.out_report.parent.mkdir(parents=True, exist_ok=True)
        report_data = {
            "total_records": len(records),
            "off_hours_count": len(off_hours_events),
            "user_stats": user_stats,
        }
        with args.out_report.open("w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        logger.info("Звіт збережено у %s", args.out_report)


if __name__ == "__main__":
    main()