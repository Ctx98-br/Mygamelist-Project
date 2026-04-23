from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated
from sqlalchemy import func as sqlfunc

import jwt
import requests
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import (
    APIKeyCookie,
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
)
from fastapi.templating import Jinja2Templates
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel
from sqlalchemy.orm import Session

from database import ForumComment, ForumPost, GameTable, GameView, UserCreate, UserTable, get_db

# --- CONFIGURAÇÕES ---
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
API_KEY = "35feb255f6ac4b88a3ed5cee84341acd"
BASE_URL = "https://api.rawg.io/api/games"

app = FastAPI(strict_slashes=False)
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
password_hash = PasswordHash.recommended()
DUMMY_HASH = password_hash.hash("dummypassword")


# --- MODELOS PYDANTIC ---
class Token(BaseModel):
    access_token: str
    token_type: str


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    date_of_birth: str | None = None
    profile_bio: str | None = None
    disabled: bool | None = None


class AdminUserCreate(BaseModel):
    nome: str
    usuario: str
    senha: str
    tipo: str = "user"
    codigo: str


class AdminUserUpdate(BaseModel):
    nome: str | None = None


class AdminStatusUpdate(BaseModel):
    ativo: bool


class ForumPostCreate(BaseModel):
    content: str


class ForumCommentCreate(BaseModel):
    content: str
    rating: int = 0  # 0-5 estrelas


class GameNotesUpdate(BaseModel):
    notes: str | None = None


class GameViewIn(BaseModel):
    game_api_id: int
    title: str
    image_url: str | None = None


# --- FUNÇÕES AUXILIARES DE SEGURANÇA ---
def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)


def get_password_hash(password):
    return password_hash.hash(password)


def authenticate_user(db: Session, username: str, password: str):
    user = db.query(UserTable).filter(UserTable.username == username).first()
    if not user:
        verify_password(password, DUMMY_HASH)
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


cookie_scheme = APIKeyCookie(name="access_token", auto_error=False)


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)] = None,
    cookie_token: Annotated[str, Depends(cookie_scheme)] = None,
    db: Session = Depends(get_db),
):
    # Tenta pegar do cabeçalho Bearer (AJAX) ou do Cookie (navegação por link)
    final_token = token or cookie_token

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Sessão expirada. Faça login novamente.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not final_token:
        raise credentials_exception

    try:
        payload = jwt.decode(final_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except InvalidTokenError:
        raise credentials_exception

    user = db.query(UserTable).filter(UserTable.username == username).first()
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Usuário desativado")
    return current_user


# --- ROTAS DE AUTENTICAÇÃO ---


@app.post("/token")
async def login_for_access_token(
    response: Response,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
) -> Token:
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Usuário ou senha incorretos")

    access_token = create_access_token(data={"sub": user.username})

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=False,  # False para o JS poder ler no cliente
        max_age=1800,    # 30 minutos
        samesite="lax",
    )

    return Token(access_token=access_token, token_type="bearer")


@app.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(UserTable).filter(UserTable.username == user.username).first():
        raise HTTPException(status_code=400, detail="Usuário já cadastrado")

    if db.query(UserTable).filter(UserTable.email == user.email).first():
        raise HTTPException(status_code=400, detail="E-mail já cadastrado")

    db_user = UserTable(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=get_password_hash(user.password),
        date_of_birth=user.date_of_birth,
        profile_bio=user.profile_bio,
    )
    db.add(db_user)
    db.commit()
    return {"message": "Usuário criado com sucesso!"}


@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Logout realizado com sucesso"}


# --- ROTAS DE PÁGINAS ---


@app.get("/", response_class=HTMLResponse)
async def catalogo_page(request: Request):
    return templates.TemplateResponse(request=request, name="catalogo.html", context={})


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request=request, name="login.html", context={})


@app.get("/registro", response_class=HTMLResponse)
async def registro_page(request: Request):
    return templates.TemplateResponse(request=request, name="registro.html", context={})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request, search: str | None = None):
    games = []
    if search:
        resp = requests.get(f"{BASE_URL}?key={API_KEY}&search={search}")
        if resp.status_code == 200:
            games = resp.json().get("results", [])

    return templates.TemplateResponse(
        request=request, name="dashboard2.html", context={"games": games}
    )


@app.get("/my-list", response_class=HTMLResponse)
async def my_list(
    request: Request,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    user_games = (
        db.query(GameTable)
        .filter(GameTable.owner_username == current_user.username)
        .all()
    )
    return templates.TemplateResponse(
        request=request, name="my_list.html", context={"games": user_games}
    )



@app.get("/forum", response_class=HTMLResponse)
async def forum_page(request: Request):
    return templates.TemplateResponse(request=request, name="forum.html", context={})


@app.get("/perfil", response_class=HTMLResponse)
async def perfil_page(request: Request):
    return templates.TemplateResponse(request=request, name="usuarios.html", context={})


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request):
    return templates.TemplateResponse(request=request, name="home-adm.html", context={})


# --- ROTAS DE API ---


@app.get("/users/me/")
async def read_users_me(
    current_user: Annotated[UserTable, Depends(get_current_active_user)],
) -> User:
    return User(
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        date_of_birth=current_user.date_of_birth,
        profile_bio=current_user.profile_bio,
        disabled=current_user.disabled,
    )


@app.post("/add-to-catalog/")
async def add_game(
    game_id: int = Form(...),
    title: str = Form(...),
    image: str = Form(...),
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    # Evita duplicatas na lista do mesmo usuário
    existing = (
        db.query(GameTable)
        .filter(
            GameTable.game_api_id == game_id,
            GameTable.owner_username == current_user.username,
        )
        .first()
    )
    if existing:
        raise HTTPException(status_code=400, detail="Jogo já está na sua lista")

    new_game = GameTable(
        game_api_id=game_id,
        title=title,
        image_url=image,
        owner_username=current_user.username,
    )
    db.add(new_game)
    db.commit()
    return {"status": "success", "message": f"{title} adicionado!"}


@app.post("/remove-from-catalog/{game_id}")
async def remove_game(
    game_id: int,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    game = (
        db.query(GameTable)
        .filter(
            GameTable.id == game_id,
            GameTable.owner_username == current_user.username,
        )
        .first()
    )
    if game:
        db.delete(game)
        db.commit()
    return RedirectResponse(url="/my-list", status_code=303)


@app.post("/rate-game/{game_id}")
async def rate_game(
    game_id: int,
    rating: int = Form(...),
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    game = (
        db.query(GameTable)
        .filter(
            GameTable.id == game_id, GameTable.owner_username == current_user.username
        )
        .first()
    )

    if not game:
        raise HTTPException(status_code=404, detail="Jogo não encontrado na sua lista")

    game.rating = rating
    db.commit()
    return {"message": "Nota atualizada!", "rating": rating}


# --- ROTAS ADMIN ---


@app.get("/admin/usuarios")
async def admin_list_users(db: Session = Depends(get_db)):
    users = db.query(UserTable).all()
    return [
        {
            "usuario": u.username,
            "nome": u.full_name or "",
            "email": u.email or "",
            "tipo": "user",
            "ativo": not u.disabled,
        }
        for u in users
    ]


@app.post("/admin/cadastro")
async def admin_create_user(payload: AdminUserCreate, db: Session = Depends(get_db)):
    ADMIN_MASTER_CODE = "mgl-admin-2025"
    if payload.codigo != ADMIN_MASTER_CODE:
        raise HTTPException(status_code=403, detail="Código mestre inválido")

    if db.query(UserTable).filter(UserTable.username == payload.usuario).first():
        raise HTTPException(status_code=400, detail="Usuário já existe")

    new_user = UserTable(
        username=payload.usuario,
        full_name=payload.nome,
        email=f"{payload.usuario}@admin.local",
        hashed_password=get_password_hash(payload.senha),
        disabled=False,
    )
    db.add(new_user)
    db.commit()
    return {"message": "Usuário criado com sucesso"}


@app.put("/admin/usuarios/{username}")
async def admin_update_user(
    username: str, payload: AdminUserUpdate, db: Session = Depends(get_db)
):
    user = db.query(UserTable).filter(UserTable.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    if payload.nome is not None:
        user.full_name = payload.nome
    db.commit()
    return {"message": "Usuário atualizado"}


@app.patch("/admin/usuarios/{username}/status")
async def admin_toggle_user_status(
    username: str, payload: AdminStatusUpdate, db: Session = Depends(get_db)
):
    user = db.query(UserTable).filter(UserTable.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    user.disabled = not payload.ativo
    db.commit()
    return {"message": "Status atualizado"}


@app.delete("/admin/usuarios/{username}")
async def admin_delete_user(username: str, db: Session = Depends(get_db)):
    user = db.query(UserTable).filter(UserTable.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    db.delete(user)
    db.commit()
    return {"message": "Usuário excluído"}


# ─────────────────────────────────────────────────────────────────────────────
# FÓRUM — Posts
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/forum/posts")
async def forum_list_posts(db: Session = Depends(get_db)):
    posts = db.query(ForumPost).order_by(ForumPost.created_at.desc()).all()
    result = []
    for p in posts:
        author = db.query(UserTable).filter(UserTable.username == p.author_username).first()
        count = db.query(ForumComment).filter(ForumComment.post_id == p.id).count()
        result.append({
            "id": p.id,
            "content": p.content,
            "author_username": p.author_username,
            "author_name": author.full_name or p.author_username if author else p.author_username,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "likes": p.likes,
            "comment_count": count,
        })
    return result


@app.post("/api/forum/posts", status_code=201)
async def forum_create_post(
    payload: ForumPostCreate,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    if not payload.content.strip():
        raise HTTPException(status_code=400, detail="Conteúdo não pode ser vazio")
    post = ForumPost(content=payload.content.strip(), author_username=current_user.username)
    db.add(post)
    db.commit()
    db.refresh(post)
    return {"id": post.id, "message": "Tópico publicado!"}


@app.post("/api/forum/posts/{post_id}/like")
async def forum_like_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    post = db.query(ForumPost).filter(ForumPost.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post não encontrado")
    post.likes += 1
    db.commit()
    return {"likes": post.likes}


# ─────────────────────────────────────────────────────────────────────────────
# FÓRUM — Comentários
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/forum/posts/{post_id}/comments")
async def forum_list_comments(post_id: int, db: Session = Depends(get_db)):
    if not db.query(ForumPost).filter(ForumPost.id == post_id).first():
        raise HTTPException(status_code=404, detail="Post não encontrado")
    comments = (
        db.query(ForumComment)
        .filter(ForumComment.post_id == post_id)
        .order_by(ForumComment.created_at.asc())
        .all()
    )
    result = []
    for c in comments:
        author = db.query(UserTable).filter(UserTable.username == c.author_username).first()
        result.append({
            "id": c.id,
            "content": c.content,
            "author_username": c.author_username,
            "author_name": author.full_name or c.author_username if author else c.author_username,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "likes": c.likes,
            "rating": c.rating or 0,
        })
    return result


@app.post("/api/forum/posts/{post_id}/comments", status_code=201)
async def forum_add_comment(
    post_id: int,
    payload: ForumCommentCreate,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    if not db.query(ForumPost).filter(ForumPost.id == post_id).first():
        raise HTTPException(status_code=404, detail="Post não encontrado")
    if not payload.content.strip():
        raise HTTPException(status_code=400, detail="Comentário não pode ser vazio")
    rating = max(0, min(5, payload.rating))
    comment = ForumComment(
        post_id=post_id,
        content=payload.content.strip(),
        author_username=current_user.username,
        rating=rating,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return {"id": comment.id, "message": "Comentário adicionado!"}


@app.post("/api/forum/posts/{post_id}/comments/{comment_id}/like")
async def forum_like_comment(
    post_id: int,
    comment_id: int,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    comment = db.query(ForumComment).filter(
        ForumComment.id == comment_id, ForumComment.post_id == post_id
    ).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Comentário não encontrado")
    comment.likes += 1
    db.commit()
    return {"likes": comment.likes}


# ─────────────────────────────────────────────────────────────────────────────
# NOTAS PESSOAIS EM JOGOS
# ─────────────────────────────────────────────────────────────────────────────

@app.patch("/api/my-list/{game_id}/notes")
async def update_game_notes(
    game_id: int,
    payload: GameNotesUpdate,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    game = db.query(GameTable).filter(
        GameTable.id == game_id,
        GameTable.owner_username == current_user.username,
    ).first()
    if not game:
        raise HTTPException(status_code=404, detail="Jogo não encontrado na sua lista")
    game.notes = payload.notes
    db.commit()
    return {"message": "Nota salva!", "notes": game.notes}


# ─────────────────────────────────────────────────────────────────────────────
# COMUNIDADE — Trending e Recentes
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/community/view")
async def record_game_view(
    payload: GameViewIn,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    """Registra que o usuário visualizou/interagiu com um jogo."""
    view = GameView(
        game_api_id=payload.game_api_id,
        title=payload.title,
        image_url=payload.image_url,
        viewer_username=current_user.username,
    )
    db.add(view)
    db.commit()
    return {"message": "ok"}


@app.get("/api/community/recent")
async def community_recent(
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    """Últimos 10 jogos únicos visualizados pelo usuário autenticado."""
    views = (
        db.query(GameView)
        .filter(GameView.viewer_username == current_user.username)
        .order_by(GameView.viewed_at.desc())
        .limit(50)
        .all()
    )
    seen, result = set(), []
    for v in views:
        if v.game_api_id not in seen:
            seen.add(v.game_api_id)
            result.append({
                "game_api_id": v.game_api_id,
                "title": v.title,
                "image_url": v.image_url,
                "viewed_at": v.viewed_at.isoformat() if v.viewed_at else None,
            })
        if len(result) >= 10:
            break
    return result


@app.get("/api/community/trending")
async def community_trending(db: Session = Depends(get_db)):
    """Top 10 jogos mais adicionados pela comunidade."""
    rows = (
        db.query(
            GameTable.game_api_id,
            GameTable.title,
            GameTable.image_url,
            sqlfunc.count(GameTable.owner_username).label("count"),
        )
        .group_by(GameTable.game_api_id, GameTable.title, GameTable.image_url)
        .order_by(sqlfunc.count(GameTable.owner_username).desc())
        .limit(10)
        .all()
    )
    return [
        {"game_api_id": r.game_api_id, "title": r.title, "image_url": r.image_url, "count": r.count}
        for r in rows
    ]


# Inclui notes no endpoint de lista JSON usada pelo perfil
@app.get("/api/my-games")
async def api_my_games(
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    games = (
        db.query(GameTable)
        .filter(GameTable.owner_username == current_user.username)
        .all()
    )
    return [
        {
            "id": g.id,
            "game_api_id": g.game_api_id,
            "title": g.title,
            "image_url": g.image_url,
            "rating": g.rating,
            "notes": g.notes,
        }
        for g in games
    ]
