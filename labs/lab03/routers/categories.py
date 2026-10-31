"""Маршрути для категорій."""

import sqlite3

from fastapi import APIRouter, HTTPException, status

from .. import repository
from ..schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["categories"])


@router.get("", response_model=list[CategoryRead])
def get_categories() -> list[dict]:
    return repository.list_categories()


@router.post("", response_model=CategoryRead, status_code=status.HTTP_201_CREATED)
def create_category(payload: CategoryCreate) -> dict:
    try:
        return repository.create_category(payload.name)
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409, detail="Категорія з такою назвою вже існує"
        )


@router.delete("/{category_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_category(category_id: int) -> None:
    try:
        ok = repository.delete_category(category_id)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Категорія містить записи")
    if not ok:
        raise HTTPException(status_code=404, detail="Категорію не знайдено")
