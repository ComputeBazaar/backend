from sqlalchemy import Column, BigInteger, Text
from sqlalchemy.dialects.postgresql import UUID
import uuid
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(BigInteger, primary_key=True)
    name = Column(Text, nullable=False)
    email = Column(Text, unique=True, nullable=False)
    api_key = Column(UUID(as_uuid=True), default=uuid.uuid4, unique=True)
    password_hash = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=True)