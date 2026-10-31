import sqlite3
from contextlib import closing
from typing import Any

from .database import get_connection

# Категорії

def create_category(name: str) -> dict[str, Any]:
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        with conn:
            cur = conn.execute("INSERT INTO categories (name) VALUES (?)", (name,))
            new_id = cur.lastrowid
        row = conn.execute("SELECT id, name FROM categories WHERE id = ?", (new_id,)).fetchone()
    return {"id": row["id"], "name": row["name"]}


def list_categories() -> list[dict[str, Any]]:
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT id, name FROM categories ORDER BY id").fetchall()
    return [{"id": r["id"], "name": r["name"]} for r in rows]


def delete_category(category_id: int) -> bool:
    with closing(get_connection()) as conn:
        with conn:
            cur = conn.execute("DELETE FROM categories WHERE id = ?", (category_id,))
        return cur.rowcount > 0


# Записи

_RECORD_SELECT = """
SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name,
       r.value, r.status
FROM records r
JOIN categories c ON c.id = r.category_id
"""


def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "code": row["code"],
        "title": row["title"],
        "category_id": row["category_id"],
        "category_name": row["category_name"],
        "value": row["value"],
        "status": row["status"],
    }


def create_record(code: str, title: str, category_id: int, value: float, status: str) -> dict[str, Any]:
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        with conn:
            cur = conn.execute(
                "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                (code, title, category_id, value, status),
            )
            new_id = cur.lastrowid
        row = conn.execute(_RECORD_SELECT + " WHERE r.id = ?", (new_id,)).fetchone()
    return _row_to_dict(row)


def get_record(record_id: int) -> dict[str, Any] | None:
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(_RECORD_SELECT + " WHERE r.id = ?", (record_id,)).fetchone()
    return _row_to_dict(row) if row else None


def list_records(category_id: int | None = None, status: str | None = None,
                 min_value: float | None = None, q: str | None = None,
                 limit: int = 20, offset: int = 0) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    if category_id is not None:
        clauses.append("r.category_id = ?")
        params.append(category_id)
    if status is not None:
        clauses.append("r.status = ?")
        params.append(status)
    if min_value is not None:
        clauses.append("r.value >= ?")
        params.append(min_value)
    if q is not None:
        clauses.append("instr(r.title, ?) > 0")
        params.append(q)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    sql = _RECORD_SELECT + where + " ORDER BY r.id LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def replace_record(record_id: int, code: str, title: str, category_id: int,
                   value: float, status: str) -> dict[str, Any] | None:
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        with conn:
            cur = conn.execute(
                "UPDATE records SET code = ?, title = ?, category_id = ?, value = ?, status = ? WHERE id = ?",
                (code, title, category_id, value, status, record_id),
            )
            if cur.rowcount == 0:
                return None
        row = conn.execute(_RECORD_SELECT + " WHERE r.id = ?", (record_id,)).fetchone()
    return _row_to_dict(row)


def delete_record(record_id: int) -> bool:
    with closing(get_connection()) as conn:
        with conn:
            cur = conn.execute("DELETE FROM records WHERE id = ?", (record_id,))
        return cur.rowcount > 0


def bulk_create_records(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Атомарно вставити пакет записів в одній транзакції."""
    created_ids: list[int] = []
    with closing(get_connection()) as conn:
        conn.row_factory = sqlite3.Row
        with conn:
            for item in items:
                cur = conn.execute(
                    "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
                    (item["code"], item["title"], item["category_id"], item["value"], item["status"]),
                )
                created_ids.append(cur.lastrowid)
        placeholders = ",".join("?" * len(created_ids))
        rows = conn.execute(_RECORD_SELECT + f" WHERE r.id IN ({placeholders}) ORDER BY r.id", created_ids).fetchall()
    return [_row_to_dict(r) for r in rows]