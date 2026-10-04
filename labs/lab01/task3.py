import csv
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

MIN_PASSWORD_LENGTH = 15
HASH_ALGORITHM = "sha384"
SALT = "00007"
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV = os.path.join(DATA_DIR, "users.csv")
LOG_JSON = os.path.join(DATA_DIR, "log.json")


class ValidationError(Exception):
    pass


def generate_hash(password: str, salt: str = "00000") -> str:

    if not password or not salt:
        raise ValueError("Password and salt cannot be empty")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        )

    combined = password + salt
    return hashlib.new(HASH_ALGORITHM, combined.encode()).hexdigest()


def create_user(username: str, password: str) -> tuple:
    """Створює кортеж (username, hash) з персональною сіллю."""
    hash_value = generate_hash(password, SALT)
    return username, hash_value


def log_event(func):

    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        log_entry = {
            "event": "login",
            "user": args[0] if args else "unknown",
            "result": "success" if result else "failure",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "args": list(args),
            "kwargs": kwargs,
        }

        os.makedirs(DATA_DIR, exist_ok=True)
        logs = []
        if os.path.exists(LOG_JSON):
            try:
                with open(LOG_JSON, "r", encoding="utf-8") as f:
                    logs = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                logs = []

        logs.append(log_entry)
        try:
            with open(LOG_JSON, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=2, ensure_ascii=False)
        except (OSError, PermissionError) as e:
            print(f"Помилка запису логу: {e}")

        return result

    return wrapper


def create_users(users_list: list) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)

    try:
        with open(USERS_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password_hash"])

            for username, password in users_list:
                try:
                    user_tuple = create_user(username, password)
                    writer.writerow(user_tuple)
                except (ValueError, ValidationError) as e:
                    print(f"Помилка створення користувача {username}: {e}")
    except (OSError, FileNotFoundError, PermissionError) as e:
        print(f"Помилка роботи з файлом: {e}")


def load_users_db() -> list:
    users_db = []

    try:
        with open(USERS_CSV, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            next(reader, None)  # пропустити заголовок
            for row in reader:
                if row:
                    users_db.append(tuple(row))
    except FileNotFoundError:
        print("Файл бази даних не знайдено")
    except (OSError, PermissionError) as e:
        print(f"Помилка читання файлу: {e}")

    return users_db


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Username and password cannot be empty")

    users_db = load_users_db()

    for stored_user, stored_hash in users_db:
        if stored_user == username:
            try:
                input_hash = generate_hash(password, SALT)
                return input_hash == stored_hash
            except (ValueError, ValidationError):
                return False

    return False


def main() -> None:
    print("Завдання 3: Хешування, CSV-база та JSON-логування")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
    print(f"Алгоритм: {HASH_ALGORITHM} | Мін. довжина: {MIN_PASSWORD_LENGTH}")
    print(f"Персональна сіль: {SALT}")

    users_to_register = [
        ("user1", "SecurePassword123!"),
        ("user2", "MyVeryLongPassword456#"),
        ("user3", "StrongSecretKey789@"),
        ("user4", "ComplexPassword012$"),
        ("user5", "HardToGuessPassword345%"),
        ("user6", "VerySecurePassword678^"),
        ("user7", "UltraSafePassword901&"),
        ("user8", "MegaSecretPassword234*"),
        ("user9", "SuperHiddenPassword567("),
        ("user10", "TopSecurityPassword890)"),
    ]

    print("\nСтворення бази користувачів...")
    create_users(users_to_register)
    print("База створена!")

    users_db = load_users_db()
    print(f"\nЗареєстровані користувачі ({len(users_db)} шт.):")
    print(f"{'Логін':<15} {'Хеш (перші 40 символів)':<45}")
    for user, hash_val in users_db:
        print(f"{user:<15} {hash_val[:40]}")

    print("Тестування автентифікації:")

    try:
        print(
            f"login('user1', 'SecurePassword123!')  -> {login('user1', 'SecurePassword123!')}"
        )
        print(
            f"login('user1', 'WrongPassword')         -> {login('user1', 'WrongPassword')}"
        )
        print(f"login('unknown', 'any')                 -> {login('unknown', 'any')}")
        print(
            f"login('user5', 'HardToGuessPassword345%') -> {login('user5', 'HardToGuessPassword345%')}"
        )
    except (ValueError, ValidationError) as e:
        print(f"Помилка: {e}")

    print(f"\nЛог подій збережено у: {LOG_JSON}")
    print(f"База користувачів у:    {USERS_CSV}")


if __name__ == "__main__":
    main()
