"""Головний FastAPI-застосунок ЛР3."""

from contextlib import asynccontextmanager

from fastapi import FastAPI

try:
    from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER
except ImportError:
    # Якщо у твоєму student.py інші назви змінних, заміни тут:
    from shared import student

    STUDENT_NAME = getattr(student, "STUDENT_NAME", "Студент")
    GROUP_NAME = getattr(student, "GROUP_NAME", "Група")
    VARIANT_NUMBER = getattr(student, "VARIANT_NUMBER", 7)

from .database import initialize_database
from .routers import categories, records


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Lab 03 — Incident Response Time Registry",
    description=(
        "Сервіс обліку часу реагування на інциденти. "
        "Одиниця вимірювання: хвилини (minutes). "
        "Поріг: 30.0."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping", tags=["health"])
def ping() -> dict:
    return {"status": "ok"}


@app.get("/student", tags=["health"])
def get_student() -> dict:
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }
