"""Початкове заповнення бази з data/seed.json (одна транзакція)."""

import json
import sqlite3
import sys
from contextlib import closing

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .database import BASE_DIR, get_connection, initialize_database

SEED_PATH = BASE_DIR / "data" / "seed.json"


class SeedCategory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: int = Field(gt=0)
    name: str = Field(min_length=2, max_length=40)


class SeedRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: float = Field(ge=0, allow_inf_nan=False)
    status: str = Field(pattern="^(new|in_progress|done)$")


class SeedData(BaseModel):
    model_config = ConfigDict(extra="forbid")
    categories: list[SeedCategory]
    records: list[SeedRecord]


def load_seed() -> SeedData:
    raw = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    return SeedData.model_validate(raw)


def is_empty(conn: sqlite3.Connection) -> bool:
    cur = conn.execute("SELECT COUNT(*) FROM categories")
    cats = cur.fetchone()[0]
    cur = conn.execute("SELECT COUNT(*) FROM records")
    recs = cur.fetchone()[0]
    return cats == 0 and recs == 0


def seed() -> None:
    initialize_database()

    try:
        data = load_seed()
    except (json.JSONDecodeError, ValidationError) as exc:
        print("Помилка в seed.json:", exc, file=sys.stderr)
        sys.exit(1)

    with closing(get_connection()) as conn:
        if not is_empty(conn):
            print("База вже заповнена. Нічого не змінено.")
            return

        try:
            with conn:
                conn.executemany(
                    "INSERT INTO categories (id, name) VALUES (?, ?)",
                    [(c.id, c.name) for c in data.categories],
                )
                conn.executemany(
                    """
                    INSERT INTO records
                        (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (r.code, r.title, r.category_id, r.value, r.status)
                        for r in data.records
                    ],
                )
        except sqlite3.IntegrityError as exc:
            print("Помилка цілісності, зміни скасовано:", exc, file=sys.stderr)
            sys.exit(2)

    print(
        f"Готово: додано {len(data.categories)} категорій "
        f"і {len(data.records)} записів."
    )


if __name__ == "__main__":
    seed()
