import os
import random
import string
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

PASSWORDS = [
    "NetworkS3c!",
    "easy",
    "Firewall@Pass",
    "anonymous",
    "Intrus10n#Detect",
    "sample",
    "Malwar3@Scan",
    "qwerty",
    "Vulnerability",
    "common",
]

CRITERIA = {
    "min_length": 9,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "easy",
    "anonymous",
    "sample",
    "qwerty",
    "common",
    "password",
}


def evaluate_password(password: str, all_passwords: list) -> str:
    if password.lower() in FORBIDDEN_PASSWORDS:
        return "Заборонений"
    if len(password) < CRITERIA["min_length"]:
        return "Заборонений"

    has_digit = any(c.isdigit() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_special = any(c in string.punctuation for c in password)

    criteria_met = sum([has_digit, has_upper, has_lower, has_special])
    all_met = all([has_digit, has_upper, has_lower, has_special])
    is_unique = all_passwords.count(password) == 1

    if all_met and len(password) >= CRITERIA["min_length"] + 4 and is_unique:
        return "Дуже сильний"
    if all_met:
        return "Сильний"
    if criteria_met >= 2:
        return "Середній"
    return "Слабкий"


def add_duplicates(passwords: list) -> list:
    """Додає 3 випадкові паролі-дублікати в кінець списку."""
    indices = random.sample(range(len(passwords)), 3)
    for idx in indices:
        passwords.append(passwords[idx])
    return passwords


def main() -> None:
    print("Завдання 1: Аналізатор надійності паролів")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")

    print(f"\nПочатковий список паролів ({len(PASSWORDS)} шт.):")
    for pwd in PASSWORDS:
        print(f"  - {pwd}")

    all_passwords = PASSWORDS.copy()
    all_passwords = add_duplicates(all_passwords)

    print(f"\nПісля додавання дублікатів ({len(all_passwords)} шт.):")
    for pwd in all_passwords:
        print(f"  - {pwd}")

    print(f"{'Пароль':<25} {'Оцінка':<20}")
    for pwd in all_passwords:
        result = evaluate_password(pwd, all_passwords)
        print(f"{pwd:<25} {result:<20}")


if __name__ == "__main__":
    main()
