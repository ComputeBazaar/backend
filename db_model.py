from sqlalchemy import Column, BigInteger, Text
from sqlalchemy.dialects.postgresql import UUID
import uuid
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(BigInteger, primary_key=True, index=True)
    name = Column(Text, nullable=False)
    email = Column(Text, nullable=False, unique=True, index=True)
    api_key = Column(UUID(as_uuid=True), unique=True, default=uuid.uuid4)
    password_hash = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=True)