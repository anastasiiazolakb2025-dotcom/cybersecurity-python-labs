"""Pydantic-моделі для запитів і відповідей API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Status = Literal["new", "in_progress", "done"]


class CategoryCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=40)


class CategoryRead(BaseModel):
    id: int
    name: str


class RecordCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=3, max_length=40)
    title: str = Field(min_length=3, max_length=120)
    category_id: int = Field(gt=0)
    value: float = Field(ge=0, allow_inf_nan=False)
    status: Status


class RecordReplace(RecordCreate):
    """PUT — усі змінювані поля обов'язкові, id немає."""


class RecordRead(BaseModel):
    id: int
    code: str
    title: str
    category_id: int
    category_name: str
    value: float
    status: Status
