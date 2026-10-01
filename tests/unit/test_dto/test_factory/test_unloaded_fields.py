from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

import msgspec
import pytest
from advanced_alchemy.extensions.litestar import SQLAlchemyDTO
from sqlalchemy import ForeignKey, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, deferred, mapped_column, relationship
from sqlalchemy.pool import StaticPool

from litestar import get
from litestar.dto import DataclassDTO, DTOConfig, register_unloaded_fields_checker
from litestar.dto._backend import DTOBackend
from litestar.dto._codegen_backend import DTOCodegenBackend
from litestar.dto._unloaded import _unloaded_fields_checkers
from litestar.exceptions import ImproperlyConfiguredException, UnloadedFieldException
from litestar.testing import create_test_client
from litestar.typing import FieldDefinition


class Base(DeclarativeBase): ...


class Author(Base):
    __tablename__ = "author"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    bio: Mapped[Optional[str]] = deferred(mapped_column(String, nullable=True))
    books: Mapped[list[Book]] = relationship(back_populates="author")


class Book(Base):
    __tablename__ = "book"
    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str]
    summary: Mapped[Optional[str]] = deferred(mapped_column(String, nullable=True))
    author_id: Mapped[int] = mapped_column(ForeignKey("author.id"))
    author: Mapped[Author] = relationship(back_populates="books")


class AuthorOmitDTO(SQLAlchemyDTO[Author]):
    config = DTOConfig(unloaded_fields_strategy="omit")


class AuthorRaiseDTO(SQLAlchemyDTO[Author]):
    config = DTOConfig(unloaded_fields_strategy="raise")


class BookRaiseDTO(SQLAlchemyDTO[Book]):
    config = DTOConfig(unloaded_fields_strategy="raise", max_nested_depth=2)


@pytest.fixture()
def engine() -> Any:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        author = Author(id=1, name="Litestar", bio=None)
        session.add(author)
        session.add(Book(id=1, title="A Book", summary="A summary", author=author))
        session.commit()
    return engine


@pytest.fixture()
def backend_cls(use_experimental_dto_backend: bool) -> type[DTOBackend]:
    return DTOCodegenBackend if use_experimental_dto_backend else DTOBackend


def make_backend(dto_cls: type, backend_cls: type[DTOBackend], model_type: type) -> DTOBackend:
    return backend_cls(
        dto_factory=dto_cls,
        field_definition=FieldDefinition.from_annotation(model_type),
        handler_id="test",
        is_data_field=False,
        model_type=model_type,
        wrapper_attribute_name=None,
    )


def encode(backend: DTOBackend, instance: Any) -> dict:
    return msgspec.json.decode(msgspec.json.encode(backend.encode_data(instance)))


def test_omit_unloaded_fields_on_detached_instance(engine: Any, backend_cls: type[DTOBackend]) -> None:
    backend = make_backend(AuthorOmitDTO, backend_cls, Author)
    with Session(engine) as session:
        author = session.get(Author, 1)
        session.close()
        # 'bio' is a deferred column and 'books' a lazy relationship; both are unloaded.
        # Reading them here would raise DetachedInstanceError - the DTO must omit them instead.
        result = encode(backend, author)
    assert result == {"id": 1, "name": "Litestar"}


def test_omit_does_not_treat_loaded_none_as_unloaded(engine: Any, backend_cls: type[DTOBackend]) -> None:
    backend = make_backend(AuthorOmitDTO, backend_cls, Author)
    with Session(engine) as session:
        author = session.get(Author, 1)
        author.bio  # loads the deferred column; its value is None
        author.books  # loads the relationship collection
        result = encode(backend, author)
    assert result["bio"] is None
    assert result["books"] == [{"id": 1, "author_id": 1, "title": "A Book"}]


def test_omit_expired_field(engine: Any, backend_cls: type[DTOBackend]) -> None:
    backend = make_backend(AuthorOmitDTO, backend_cls, Author)
    with Session(engine) as session:
        author = session.get(Author, 1)
        session.expire(author, ["name"])
        session.close()
        result = encode(backend, author)
    assert result == {"id": 1}


def test_raise_unloaded_field_on_detached_instance(engine: Any, backend_cls: type[DTOBackend]) -> None:
    backend = make_backend(AuthorRaiseDTO, backend_cls, Author)
    with Session(engine) as session:
        author = session.get(Author, 1)
        session.close()
        with pytest.raises(UnloadedFieldException) as exc_info:
            backend.encode_data(author)
    assert exc_info.value.field_path in {"bio", "books"}
    assert exc_info.value.field_path in str(exc_info.value)


def test_raise_nested_field_path(engine: Any, backend_cls: type[DTOBackend]) -> None:
    backend = make_backend(BookRaiseDTO, backend_cls, Book)
    with Session(engine) as session:
        book = session.get(Book, 1)
        book.summary  # load the book's own deferred column
        book.author  # load the relationship; the author's fields remain unloaded
        with pytest.raises(UnloadedFieldException) as exc_info:
            backend.encode_data(book)
    assert exc_info.value.field_path == "author.bio"


def test_raise_collection_item_field_path(engine: Any, backend_cls: type[DTOBackend]) -> None:
    backend = make_backend(AuthorRaiseDTO, backend_cls, Author)
    with Session(engine) as session:
        author = session.get(Author, 1)
        author.bio  # load the author's own deferred column
        author.books  # load the collection; each book's 'summary' column remains deferred
        with pytest.raises(UnloadedFieldException) as exc_info:
            backend.encode_data(author)
    assert exc_info.value.field_path == "books.0.summary"


def test_raise_expired_field(engine: Any, backend_cls: type[DTOBackend]) -> None:
    backend = make_backend(AuthorRaiseDTO, backend_cls, Author)
    with Session(engine) as session:
        author = session.get(Author, 1)
        author.bio
        author.books
        for book in author.books:
            book.summary
        session.expire(author, ["name"])
        session.close()
        with pytest.raises(UnloadedFieldException) as exc_info:
            backend.encode_data(author)
    assert exc_info.value.field_path == "name"


def make_collection_backend(dto_cls: type, backend_cls: type[DTOBackend], model_type: type) -> DTOBackend:
    return backend_cls(
        dto_factory=dto_cls,
        field_definition=FieldDefinition.from_annotation(list[model_type]),
        handler_id="test",
        is_data_field=False,
        model_type=model_type,
        wrapper_attribute_name=None,
    )


def test_omit_unloaded_fields_on_model_collection(engine: Any, backend_cls: type[DTOBackend]) -> None:
    backend = make_collection_backend(AuthorOmitDTO, backend_cls, Author)
    with Session(engine) as session:
        author = session.get(Author, 1)
        session.close()
        result = msgspec.json.decode(msgspec.json.encode(backend.encode_data([author])))
    assert result == [{"id": 1, "name": "Litestar"}]


def test_raise_unloaded_field_on_model_collection(engine: Any, backend_cls: type[DTOBackend]) -> None:
    backend = make_collection_backend(AuthorRaiseDTO, backend_cls, Author)
    with Session(engine) as session:
        author = session.get(Author, 1)
        author.bio
        author.books
        for book in author.books:
            book.summary
        session.expire(author, ["name"])
        session.close()
        with pytest.raises(UnloadedFieldException) as exc_info:
            backend.encode_data([author])
    assert exc_info.value.field_path == "0.name"


def test_no_strategy_keeps_default_behavior(engine: Any, backend_cls: type[DTOBackend]) -> None:
    class AuthorDTO(SQLAlchemyDTO[Author]):
        config = DTOConfig()

    backend = make_backend(AuthorDTO, backend_cls, Author)
    with Session(engine) as session:
        author = session.get(Author, 1)
        # without a strategy, unloaded fields are read as before, lazy-loading within the session
        result = encode(backend, author)
    assert result["bio"] is None
    assert len(result["books"]) == 1


def test_invalid_strategy_raises() -> None:
    with pytest.raises(ImproperlyConfiguredException, match="unloaded_fields_strategy"):
        DTOConfig(unloaded_fields_strategy="invalid")  # type: ignore[arg-type]


def test_data_backend_ignores_strategy(backend_cls: type[DTOBackend]) -> None:
    backend = backend_cls(
        dto_factory=AuthorOmitDTO,
        field_definition=FieldDefinition.from_annotation(Author),
        handler_id="test",
        is_data_field=True,
        model_type=Author,
        wrapper_attribute_name=None,
    )
    assert backend.unloaded_fields_strategy is None


def test_custom_unloaded_fields_checker(backend_cls: type[DTOBackend]) -> None:
    @dataclass
    class CustomModel:
        a: int
        b: str

    class CustomModelDTO(DataclassDTO[CustomModel]):
        config = DTOConfig(unloaded_fields_strategy="omit")

    def checker(instance: Any) -> Any:
        if isinstance(instance, CustomModel):
            return {"b"}
        return None

    register_unloaded_fields_checker(checker)
    try:
        backend = make_backend(CustomModelDTO, backend_cls, CustomModel)
        assert encode(backend, CustomModel(a=1, b="two")) == {"a": 1}
    finally:
        _unloaded_fields_checkers.remove(checker)


def test_get_unloaded_fields_override(backend_cls: type[DTOBackend]) -> None:
    @dataclass
    class CustomModel:
        a: int
        b: str

    class CustomModelDTO(DataclassDTO[CustomModel]):
        config = DTOConfig(unloaded_fields_strategy="raise")

        @classmethod
        def get_unloaded_fields(cls, instance: Any) -> Any:
            return {"b"}

    backend = make_backend(CustomModelDTO, backend_cls, CustomModel)
    with pytest.raises(UnloadedFieldException) as exc_info:
        backend.encode_data(CustomModel(a=1, b="two"))
    assert exc_info.value.field_path == "b"


def test_omit_strategy_response_with_closed_session(engine: Any, use_experimental_dto_backend: bool) -> None:
    class AuthorDTO(SQLAlchemyDTO[Author]):
        config = DTOConfig(
            unloaded_fields_strategy="omit",
            experimental_codegen_backend=use_experimental_dto_backend,
        )

    @get("/author", dto=AuthorDTO, sync_to_thread=False)
    def get_author() -> Author:
        with Session(engine) as session:
            author = session.get(Author, 1)
            session.close()
            return author

    with create_test_client(route_handlers=[get_author]) as client:
        response = client.get("/author")
        assert response.status_code == 200
        assert response.json() == {"id": 1, "name": "Litestar"}


def test_raise_strategy_response_with_closed_session(engine: Any, use_experimental_dto_backend: bool) -> None:
    class AuthorDTO(SQLAlchemyDTO[Author]):
        config = DTOConfig(
            unloaded_fields_strategy="raise",
            experimental_codegen_backend=use_experimental_dto_backend,
        )

    @get("/author", dto=AuthorDTO, sync_to_thread=False)
    def get_author() -> Author:
        with Session(engine) as session:
            author = session.get(Author, 1)
            session.close()
            return author

    with create_test_client(route_handlers=[get_author], raise_server_exceptions=False) as client:
        response = client.get("/author")
        assert response.status_code == 500
