from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import DateTime, Integer, LargeBinary, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class BaseModel(DeclarativeBase):
    pass


class Password(BaseModel):
    __tablename__ = "password"

    pid: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    service: Mapped[str] = mapped_column(Text, index=True)
    username: Mapped[str] = mapped_column(Text, index=True)
    email: Mapped[Optional[str]] = mapped_column(Text, index=True, nullable=True, default=None)
    password: Mapped[bytes] = mapped_column(LargeBinary)
    tag: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    link: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    category: Mapped[Optional[str]] = mapped_column(Text, nullable=True, default=None)
    note: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True, default=None)
    pcreated: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    pupdated: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, default=None)