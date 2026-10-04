import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

USERS = {
    "incident_commander": {
        "role": "incident_response",
        "clearance": 4,
        "department": "CSIRT",
        "active": True,
    },
    "malware_analyst": {
        "role": "malware_researcher",
        "clearance": 3,
        "department": "Research",
        "active": True,
    },
    "monitoring_tech": {
        "role": "monitoring",
        "clearance": 2,
        "department": "NOC",
        "active": True,
    },
    "customer_rep": {
        "role": "customer_service",
        "clearance": 1,
        "department": "Customer",
        "active": True,
    },
    "backup_service": {
        "role": "service_account",
        "clearance": 2,
        "department": "System",
        "active": False,
    },
}

RESOURCES = [
    ("incident_playbook", 4),
    ("malware_lab", 3),
    ("monitoring_dashboards", 2),
    ("customer_portal", 1),
    ("emergency_procedures", 4),
    ("service_desk", 1),
    ("reverse_engineering", 3),
    ("alert_systems", 2),
    ("escalation_matrix", 3),
    ("knowledge_base", 1),
]

SECURITY_LEVELS = ("Public Access", "Authorized", "Privileged", "Critical")

BLOCKED_USERS = {"backup_service", "deactivated_svc", "policy_violation"}


def check_access(username: str, resource_level: int) -> tuple:

    if username not in USERS:
        return "DENY", "User not found"

    user_data = USERS[username]

    if username in BLOCKED_USERS:
        return "DENY", "User is blocked"

    if not user_data.get("active", False):
        return "DENY", "Account inactive"

    if user_data.get("clearance", 0) >= resource_level:
        return "ALLOW", None

    return "DENY", "Insufficient clearance"


def main() -> None:
    print("Завдання 2: Багаторівнева система контролю доступу")
    print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")

    print("\nРесурси системи:")
    for name, level in RESOURCES:
        level_name = SECURITY_LEVELS[level - 1]
        print(f"  {name:<25} -> {level_name}")

    print("Результати перевірки доступу:")

    for username in USERS:
        for resource_name, resource_level in RESOURCES:
            result, reason = check_access(username, resource_level)
            if result == "ALLOW":
                print(f"user=[{username}] resource=[{resource_name}] -> ALLOW")
            else:
                print(
                    f"user=[{username}] resource=[{resource_name}] -> DENY ({reason})"
                )


if __name__ == "__main__":
    main()
