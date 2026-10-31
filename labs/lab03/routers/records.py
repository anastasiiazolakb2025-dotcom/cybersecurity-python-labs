"""Маршрути для записів."""

import sqlite3

from fastapi import APIRouter, HTTPException, Query, status

from .. import repository
from ..schemas import RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/records", tags=["records"])


@router.get("", response_model=list[RecordRead])
def get_records(
    category_id: int | None = Query(default=None, gt=0),
    status_: str | None = Query(
        default=None, alias="status", pattern="^(new|in_progress|done)$"
    ),
    min_value: float | None = Query(default=None, ge=0),
    q: str | None = Query(default=None, min_length=1, max_length=120),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    return repository.list_records(
        category_id=category_id,
        status=status_,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.get("/{record_id}", response_model=RecordRead)
def get_record(record_id: int) -> dict:
    record = repository.get_record(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    return record


@router.post("", response_model=RecordRead, status_code=status.HTTP_201_CREATED)
def create_record(payload: RecordCreate) -> dict:
    try:
        return repository.create_record(
            payload.code,
            payload.title,
            payload.category_id,
            payload.value,
            payload.status,
        )
    except sqlite3.IntegrityError as exc:
        msg = str(exc).lower()
        if "foreign key" in msg:
            raise HTTPException(status_code=404, detail="Категорію не знайдено")
        raise HTTPException(status_code=409, detail="Дублікат code")


@router.put("/{record_id}", response_model=RecordRead)
def replace_record(record_id: int, payload: RecordReplace) -> dict:
    try:
        record = repository.replace_record(
            record_id,
            payload.code,
            payload.title,
            payload.category_id,
            payload.value,
            payload.status,
        )
    except sqlite3.IntegrityError as exc:
        msg = str(exc).lower()
        if "foreign key" in msg:
            raise HTTPException(status_code=404, detail="Категорію не знайдено")
        raise HTTPException(status_code=409, detail="Дублікат code")
    if record is None:
        raise HTTPException(status_code=404, detail="Запис не знайдено")
    return record


@router.delete("/{record_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_record(record_id: int) -> None:
    if not repository.delete_record(record_id):
        raise HTTPException(status_code=404, detail="Запис не знайдено")


@router.post(
    "/bulk", response_model=list[RecordRead], status_code=status.HTTP_201_CREATED
)
def bulk_create(payload: list[RecordCreate]) -> list[dict]:
    if not (1 <= len(payload) <= 100):
        raise HTTPException(
            status_code=422, detail="Пакет має містити від 1 до 100 елементів"
        )
    items = [p.model_dump() for p in payload]
    try:
        return repository.bulk_create_records(items)
    except sqlite3.IntegrityError as exc:
        msg = str(exc).lower()
        if "foreign key" in msg:
            raise HTTPException(status_code=404, detail="Категорію не знайдено")
        raise HTTPException(status_code=409, detail="Дублікат code у пакеті або базі")
