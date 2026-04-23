import os
from datetime import datetime

from pydantic import BaseModel
from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey,
    Integer, String, Text, create_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

SQLALCHEMY_DATABASE_URL = os.getenv(
    "DATABASE_URL", "postgresql://admin:9742PTGs@db:5432/mygamelist"
)

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ── Usuários ──────────────────────────────────────────────────────────────────
class UserTable(Base):
    __tablename__ = "users"
    username      = Column(String,  primary_key=True, index=True)
    email         = Column(String,  unique=True, index=True)
    full_name     = Column(String)
    hashed_password = Column(String)
    disabled      = Column(Boolean, default=False)
    date_of_birth = Column(String,  nullable=True)
    profile_bio   = Column(String,  nullable=True)


# ── Jogos do usuário ──────────────────────────────────────────────────────────
class GameTable(Base):
    __tablename__ = "my_games"
    id             = Column(Integer, primary_key=True, index=True)
    game_api_id    = Column(Integer)
    title          = Column(String)
    image_url      = Column(String)
    owner_username = Column(String, ForeignKey("users.username"))
    rating         = Column(Integer, default=0)
    notes          = Column(Text,    nullable=True)   # ← NOVO: anotações pessoais


# ── Histórico de visualizações (trending + recentes) ─────────────────────────
class GameView(Base):
    __tablename__ = "game_views"
    id              = Column(Integer,  primary_key=True, index=True)
    game_api_id     = Column(Integer,  index=True)
    title           = Column(String)
    image_url       = Column(String,   nullable=True)
    viewer_username = Column(String,   ForeignKey("users.username"))
    viewed_at       = Column(DateTime, default=datetime.utcnow)


# ── Fórum: tópicos ────────────────────────────────────────────────────────────
class ForumPost(Base):
    __tablename__    = "forum_posts"
    id               = Column(Integer,  primary_key=True, index=True)
    content          = Column(Text,     nullable=False)
    author_username  = Column(String,   ForeignKey("users.username"))
    created_at       = Column(DateTime, default=datetime.utcnow)
    likes            = Column(Integer,  default=0)


# ── Fórum: comentários ────────────────────────────────────────────────────────
class ForumComment(Base):
    __tablename__   = "forum_comments"
    id              = Column(Integer,  primary_key=True, index=True)
    post_id         = Column(Integer,  ForeignKey("forum_posts.id", ondelete="CASCADE"))
    content         = Column(Text,     nullable=False)
    author_username = Column(String,   ForeignKey("users.username"))
    created_at      = Column(DateTime, default=datetime.utcnow)
    likes           = Column(Integer,  default=0)
    rating          = Column(Integer,  default=0)   # avaliação por estrelas (0-5)


# ── Pydantic para cadastro ────────────────────────────────────────────────────
class UserCreate(BaseModel):
    username:      str
    email:         str
    password:      str
    full_name:     str | None = None
    date_of_birth: str | None = None
    profile_bio:   str | None = None


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Cria todas as tabelas (idempotente)
Base.metadata.create_all(bind=engine)
