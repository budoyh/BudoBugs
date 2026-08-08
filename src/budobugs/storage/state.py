"""SQLite document state whose truth can be rebuilt from artifacts and events."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel
from sqlalchemy import DateTime, Integer, String, Text, create_engine, event, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

ModelT = TypeVar("ModelT", bound=BaseModel)


class Base(DeclarativeBase):
    pass


class DocumentRecord(Base):
    __tablename__ = "documents"

    key: Mapped[str] = mapped_column(String(256), primary_key=True)
    kind: Mapped[str] = mapped_column(String(80), index=True)
    document_id: Mapped[str] = mapped_column(String(128), index=True)
    payload: Mapped[str] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class StoredEvent(Base):
    __tablename__ = "events"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class StateStore:
    """Small typed document repository with transactional writes."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.engine = create_engine(
            f"sqlite:///{path.as_posix()}",
            future=True,
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(self.engine, "connect")
        def configure_sqlite(dbapi_connection: object, _connection_record: object) -> None:
            cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=FULL")
            cursor.close()

        Base.metadata.create_all(self.engine)

    @staticmethod
    def _key(kind: str, document_id: str) -> str:
        return f"{kind}:{document_id}"

    def save(self, kind: str, document_id: str, value: BaseModel) -> None:
        payload = value.model_dump_json()
        now = datetime.now(UTC)
        with Session(self.engine) as session, session.begin():
            key = self._key(kind, document_id)
            existing = session.get(DocumentRecord, key)
            if existing is None:
                session.add(
                    DocumentRecord(
                        key=key,
                        kind=kind,
                        document_id=document_id,
                        payload=payload,
                        updated_at=now,
                    )
                )
            else:
                existing.payload = payload
                existing.updated_at = now

    def load(self, kind: str, document_id: str, model: type[ModelT]) -> ModelT | None:
        with Session(self.engine) as session:
            record = session.get(DocumentRecord, self._key(kind, document_id))
            return None if record is None else model.model_validate_json(record.payload)

    def list(self, kind: str, model: type[ModelT]) -> list[ModelT]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(DocumentRecord).where(DocumentRecord.kind == kind).order_by(DocumentRecord.key)
            )
            return [model.model_validate_json(row.payload) for row in rows]

    def delete(self, kind: str, document_id: str) -> bool:
        with Session(self.engine) as session, session.begin():
            record = session.get(DocumentRecord, self._key(kind, document_id))
            if record is None:
                return False
            session.delete(record)
            return True

    def record_event(self, event_id: str, event_type: str, payload: str) -> None:
        with Session(self.engine) as session, session.begin():
            session.add(
                StoredEvent(
                    event_id=event_id,
                    event_type=event_type,
                    payload=payload,
                    created_at=datetime.now(UTC),
                )
            )

    def replace_from_documents(self, documents: Iterable[tuple[str, str, BaseModel]]) -> None:
        """Atomically refresh a selected materialized snapshot."""

        with Session(self.engine) as session, session.begin():
            for kind, document_id, value in documents:
                key = self._key(kind, document_id)
                record = session.get(DocumentRecord, key)
                payload = value.model_dump_json()
                if record is None:
                    session.add(
                        DocumentRecord(
                            key=key,
                            kind=kind,
                            document_id=document_id,
                            payload=payload,
                            updated_at=datetime.now(UTC),
                        )
                    )
                else:
                    record.payload = payload
                    record.updated_at = datetime.now(UTC)
