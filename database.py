import os

from pydantic import BaseModel
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://admin:9742PTGs@db:5432/mygamelist"
)

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class UserTable(Base):
    __tablename__ = "users"
    username = Column(String, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=False)


class UserCreate(BaseModel):
    username: str
    email: str
    password: str  # Senha limpa que vem do formulário
    full_name: str | None = None


# Cria a tabela no Postgres
Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class GameTable(Base):
    __tablename__ = "my_games"
    id = Column(Integer, primary_key=True, index=True)
    game_api_id = Column(Integer)  # ID que vem da RAWG/IGDB
    title = Column(String)
    image_url = Column(String)
    owner_username = Column(String, ForeignKey("users.username"))


# Cria a tabela no Postgres
Base.metadata.create_all(bind=engine)
