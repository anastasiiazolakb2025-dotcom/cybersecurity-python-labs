import sys
from datetime import UTC, datetime, timedelta

# Імпортуємо класи
from labs.lab02.task1 import Admin, User, UserAccount


def demo():
    print("Завдання 1: Демо")

    user = User("ivan", "ivan@example.com")
    user.set_password("MyPass123")
    acc = UserAccount(user)

    print("Спроба входу з поганим паролем:", acc.login("ivan", "wrong", "127.0.0.1"))
    print("Спроба входу з добрим паролем:", acc.login("ivan", "MyPass123", "127.0.0.1"))
    print("Статус авторизації:", acc.is_authenticated())

    try:
        user.email = "поганий_email"
    except ValueError as e:
        print("Помилка email:", e)

    admin = Admin("root", "root@example.com", {"read"})
    admin.grant_permission("write")
    print(admin)

    if acc.session:
        acc.session.last_activity = datetime.now(UTC) - timedelta(seconds=1000)
    print("Статус після таймауту:", acc.is_authenticated())

    acc.logout()

    print("\n Журнал аудиту")
    acc.audit.show_all()


def analyze():
    from labs.lab02 import task2

    task2.main()


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("demo", "analyze"):
        print("Використання: python -m labs.lab02.main {demo|analyze}")
        sys.exit(1)

    if sys.argv[1] == "demo":
        demo()
    else:
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        analyze()
