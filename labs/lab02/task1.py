import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

# Константи для паролів
ITERATIONS = 100_000
SESSION_TIMEOUT_SEC = 900

# Регулярний вираз для email
EMAIL_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class User:
    def __init__(self, username, email, role="user"):
        self.username = username
        self.email = email
        self.role = role
        self.active = True
        self.__password_hash = b""
        self.__password_salt = b""

    def set_password(self, password):
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), self.__password_salt, ITERATIONS
        )

    def check_password(self, password):
        if not self.__password_hash:
            return False
        test_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), self.__password_salt, ITERATIONS
        )
        return hmac.compare_digest(test_hash, self.__password_hash)

    def deactivate(self):
        self.active = False

    @property
    def email(self):
        return self._email

    @email.setter
    def email(self, value):
        if not EMAIL_PATTERN.match(value):
            raise ValueError("Неправильний формат email")
        self._email = value

    def __str__(self):
        return f"User({self.username}, {self.email}, {self.role})"


class Admin(User):
    def __init__(self, username, email, permissions=None):
        super().__init__(username, email, role="admin")
        if permissions is None:
            self.permissions = set()
        else:
            self.permissions = set(permissions)

    def grant_permission(self, permission):
        self.permissions.add(permission)

    def revoke_permission(self, permission):
        self.permissions.discard(permission)

    def has_permission(self, permission):
        return permission in self.permissions

    def __str__(self):
        return f"{super().__str__()} | Права: {self.permissions}"


class Session:
    def __init__(self, ip):
        self.ip = ip
        now = datetime.now(UTC)
        self.login_time = now
        self.last_activity = now

    def touch(self):
        self.last_activity = datetime.now(UTC)

    def is_active(self, timeout_sec):
        if timeout_sec <= 0:
            raise ValueError("Таймаут має бути більше 0")
        diff = datetime.now(UTC) - self.last_activity
        return diff <= timedelta(seconds=timeout_sec)


@dataclass
class AuditRecord:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self.records = []

    def add_log(self, username, action):
        record = AuditRecord(
            timestamp=datetime.now(UTC), username=username, action=action
        )
        self.records.append(record)

    def show_all(self):
        for r in self.records:
            print(f"  [{r.timestamp.isoformat()}] {r.username} - {r.action}")


class UserAccount:
    def __init__(self, user):
        self.user = user
        self.audit = AuditLog()
        self.session = None

    def login(self, username, password, ip):
        if not self.user.active:
            self.audit.add_log(username, "login_failure: inactive")
            return False

        if username == self.user.username and self.user.check_password(password):
            self.session = Session(ip)
            self.audit.add_log(username, "login_success")
            return True
        else:
            self.audit.add_log(username, "login_failure: bad_password")
            return False

    def is_authenticated(self):
        if self.session is None:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self):
        if self.session is not None:
            self.session = None
            self.audit.add_log(self.user.username, "logout")

    def __getitem__(self, key):
        if key == "user":
            return self.user
        elif key == "session":
            return self.session
        elif key == "audit":
            return self.audit
        elif key == "username":
            return self.user.username
        else:
            raise KeyError(f"Ключ {key} недоступний")

    def __setitem__(self, key, value):
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Має бути об'єкт User")
            self.user = value
        elif key == "active":
            if not isinstance(value, bool):
                raise TypeError("Має бути bool")
            self.user.active = value
        else:
            raise KeyError(f"Ключ {key} не можна змінювати")
