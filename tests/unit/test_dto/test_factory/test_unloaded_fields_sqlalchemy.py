from __future__ import annotations

from typing import Any, Optional, TypeVar

import pytest

pytest.importorskip("sqlalchemy")
pytest.importorskip("advanced_alchemy")

import sqlalchemy as sa
from advanced_alchemy.extensions.litestar import SQLAlchemyDTO, SQLAlchemyDTOConfig
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, selectinload, undefer
from sqlalchemy.pool import StaticPool

from litestar import Litestar, get
from litestar.exceptions.dto_exceptions import UnloadedFieldException
from litestar.serialization import encode_json
from litestar.testing import TestClient
from litestar.typing import FieldDefinition

T = TypeVar("T")


class Base(DeclarativeBase): ...


class Author(Base):
    __tablename__ = "author"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    bio: Mapped[Optional[str]] = mapped_column(deferred=True)
    books: Mapped[list[Book]] = relationship(back_populates="author")


class Book(Base):
    __tablename__ = "book"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str]
    author_id: Mapped[int] = mapped_column(sa.ForeignKey("author.id"))
    author: Mapped[Author] = relationship(back_populates="books")


class LoadedAwareSQLAlchemyDTO(SQLAlchemyDTO[T]):
    """SQLAlchemy DTO that detects unloaded attributes without accessing them."""

    @classmethod
    def is_field_loaded(cls, instance: Any, field_name: str) -> bool:
        inspection = sa.inspect(instance, raiseerr=False)
        if inspection is None:
            return True
        return field_name not in inspection.unloaded


@pytest.fixture()
def engine() -> sa.Engine:
    engine = sa.create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        author = Author(id=1, name="Litestar", bio=None)
        author.books = [Book(id=1, title="Book")]
        session.add(author)
        session.commit()
    return engine


def make_backend(strategy: Any, use_experimental_dto_backend: bool, handler_id: str = "test") -> Any:
    class AuthorDTO(LoadedAwareSQLAlchemyDTO[Author]):
        config = SQLAlchemyDTOConfig(
            unloaded_fields_strategy=strategy,
            experimental_codegen_backend=use_experimental_dto_backend,
        )

    AuthorDTO.create_for_field_definition(FieldDefinition.from_annotation(Author), handler_id=handler_id)
    return AuthorDTO._dto_backends[handler_id]["return_backend"]


def test_omit_unloaded_fields(engine: sa.Engine, use_experimental_dto_backend: bool) -> None:
    backend = make_backend("omit", use_experimental_dto_backend)
    with Session(engine) as session:
        author = session.get(Author, 1)  # 'bio' (deferred) and 'books' (relationship) are not loaded
        assert encode_json(backend.encode_data(author)) == b'{"id":1,"name":"Litestar"}'


def test_raise_for_unloaded_field(engine: sa.Engine, use_experimental_dto_backend: bool) -> None:
    backend = make_backend("raise", use_experimental_dto_backend)
    with Session(engine) as session:
        author = session.get(Author, 1)
        with pytest.raises(UnloadedFieldException) as exc_info:
            backend.encode_data(author)
    assert exc_info.value.field_path == "bio"


def test_loaded_none_field_is_serialized(engine: sa.Engine, use_experimental_dto_backend: bool) -> None:
    backend = make_backend("omit", use_experimental_dto_backend)
    with Session(engine) as session:
        author = session.execute(
            sa.select(Author).options(undefer(Author.bio), selectinload(Author.books))
        ).scalar_one()
        assert encode_json(backend.encode_data(author)) == (
            b'{"id":1,"bio":null,"books":[{"id":1,"author_id":1,"title":"Book"}],"name":"Litestar"}'
        )


def test_expired_field_is_unloaded(engine: sa.Engine, use_experimental_dto_backend: bool) -> None:
    backend = make_backend("omit", use_experimental_dto_backend)
    with Session(engine) as session:
        author = session.execute(
            sa.select(Author).options(undefer(Author.bio), selectinload(Author.books))
        ).scalar_one()
        session.expire(author, ["name"])
        assert encode_json(backend.encode_data(author)) == (
            b'{"id":1,"bio":null,"books":[{"id":1,"author_id":1,"title":"Book"}]}'
        )


def test_nested_unloaded_field_path(engine: sa.Engine, use_experimental_dto_backend: bool) -> None:
    backend = make_backend("raise", use_experimental_dto_backend)
    with Session(engine) as session:
        author = session.execute(
            sa.select(Author).options(undefer(Author.bio), selectinload(Author.books))
        ).scalar_one()
        session.expire(author.books[0], ["title"])
        with pytest.raises(UnloadedFieldException) as exc_info:
            backend.encode_data(author)
    assert exc_info.value.field_path == "books.title"


def test_omit_unloaded_field_in_nested_collection(engine: sa.Engine, use_experimental_dto_backend: bool) -> None:
    backend = make_backend("omit", use_experimental_dto_backend)
    with Session(engine) as session:
        author = session.execute(
            sa.select(Author).options(undefer(Author.bio), selectinload(Author.books))
        ).scalar_one()
        session.expire(author.books[0], ["title"])
        assert encode_json(backend.encode_data(author)) == (
            b'{"id":1,"bio":null,"books":[{"id":1,"author_id":1}],"name":"Litestar"}'
        )


def test_detached_instance_omit(engine: sa.Engine, use_experimental_dto_backend: bool) -> None:
    backend = make_backend("omit", use_experimental_dto_backend)
    session = Session(engine)
    author = session.execute(sa.select(Author).options(undefer(Author.bio))).scalar_one()
    session.close()
    # 'books' is not loaded and the connection is closed; accessing it would raise
    # 'DetachedInstanceError'. It is omitted instead.
    assert encode_json(backend.encode_data(author)) == b'{"id":1,"bio":null,"name":"Litestar"}'


def test_detached_instance_raise(engine: sa.Engine, use_experimental_dto_backend: bool) -> None:
    backend = make_backend("raise", use_experimental_dto_backend)
    session = Session(engine)
    author = session.execute(sa.select(Author).options(undefer(Author.bio))).scalar_one()
    session.close()
    with pytest.raises(UnloadedFieldException) as exc_info:
        backend.encode_data(author)
    assert exc_info.value.field_path == "books"


def test_serialization_via_app(engine: sa.Engine, use_experimental_dto_backend: bool) -> None:
    class AuthorDTO(LoadedAwareSQLAlchemyDTO[Author]):
        config = SQLAlchemyDTOConfig(
            unloaded_fields_strategy="omit",
            experimental_codegen_backend=use_experimental_dto_backend,
        )

    @get("/author", dto=AuthorDTO, sync_to_thread=False)
    def get_author() -> Author:
        with Session(engine) as session:
            author = session.get(Author, 1)
            session.expunge(author)
        return author

    with TestClient(Litestar([get_author])) as client:
        response = client.get("/author")
        assert response.status_code == 200
        assert response.json() == {"id": 1, "name": "Litestar"}
