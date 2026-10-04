import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


def print_header() -> None:
    print("ЛАБОРАТОРНА РОБОТА №1")
    print("Основи розробки на Python, Git та стандарти стилю коду")
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група:   {GROUP_NAME}")
    print(f"Варіант: {VARIANT_NUMBER}")


def run_task(module_name: str, title: str) -> None:
    print(f"# {title}")

    try:
        module = __import__(module_name, fromlist=["main"])
        module.main()
    except ImportError as e:
        print(f"Помилка імпорту модуля {module_name}: {e}")
    except Exception as e:
        print(f"Помилка виконання {module_name}: {e}")


def main() -> None:
    """Головна функція — запускає всі три завдання."""
    print_header()

    run_task("task1", "Завдання 1: Аналізатор надійності паролів")
    run_task("task2", "Завдання 2: Багаторівнева система контролю доступу")
    run_task("task3", "Завдання 3: Хешування, CSV-база та JSON-логування")

    print("Усі завдання виконано!")

if __name__ == "__main__":
    main()
