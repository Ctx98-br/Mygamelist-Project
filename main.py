from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

import jwt
import requests
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
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

from database import Base, GameTable, UserCreate, UserTable, engine, get_db

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
    # Tenta pegar do cabeçalho (AJAX) ou do Cookie (Clique em link)
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
    response: Response,  # Adicione esse parâmetro
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db),
) -> Token:
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Usuário ou senha incorretos")

    access_token = create_access_token(data={"sub": user.username})

    # MUDANÇA AQUI: Salva o token no Cookie do navegador
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=False,  # Deixe False para o seu JS ainda conseguir ler se precisar
        max_age=1800,  # 30 minutos
    )

    return Token(access_token=access_token, token_type="bearer")


@app.post("/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(UserTable).filter(UserTable.username == user.username).first():
        raise HTTPException(status_code=400, detail="Usuário já cadastrado")

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


# --- ROTAS DE PÁGINAS ---


@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    # Agora usamos TemplateResponse em vez de FileResponse
    return templates.TemplateResponse(request=request, name="login.html", context={})


@app.get("/registro", response_class=HTMLResponse)
async def registro_page(request: Request):
    return templates.TemplateResponse(request=request, name="registro.html", context={})


@app.get("/users/me/")  # <-- Verifique se a barra final está aqui
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)],
) -> User:
    return current_user


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request, search: str = None):
    # Verifique se o search não está vindo vazio ou estranho
    games = []
    if search:
        # Debug: print(f"Buscando por: {search}")
        response = requests.get(f"{BASE_URL}?key={API_KEY}&search={search}")
        if response.status_code == 200:
            games = response.json().get("results", [])

    return templates.TemplateResponse(
        request=request, name="dashboard2.html", context={"games": games}
    )


# --- ROTAS DE AÇÃO ---


@app.post("/add-to-catalog/")
async def add_game(
    game_id: int = Form(...),
    title: str = Form(...),
    image: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    new_game = GameTable(
        game_api_id=game_id,
        title=title,
        image_url=image,
        owner_username=current_user.username,
    )
    db.add(new_game)
    db.commit()
    return {"status": "success", "message": f"{title} adicionado!"}


@app.get("/my-list", response_class=HTMLResponse)
async def my_list(
    request: Request,
    db: Session = Depends(get_db),
    # Adicionamos a proteção aqui também para saber quem está acessando
    current_user: User = Depends(get_current_active_user),
):
    # Busca apenas os jogos do usuário que está logado
    user_games = (
        db.query(GameTable)
        .filter(GameTable.owner_username == current_user.username)
        .all()
    )

    return templates.TemplateResponse(
        request=request, name="my_list.html", context={"games": user_games}
    )


# ROTA PARA REMOVER (Ação)
@app.post("/remove-from-catalog/{game_id}")
async def remove_game(game_id: int, db: Session = Depends(get_db)):
    game = db.query(GameTable).filter(GameTable.id == game_id).first()
    if game:
        db.delete(game)
        db.commit()
    return RedirectResponse(url="/my-list", status_code=303)


@app.post("/rate-game/{game_id}")
async def rate_game(
    game_id: int,
    rating: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
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
    return {"message": "Nota atualizada!"}


@app.get("/my-list", response_class=HTMLResponse)
async def view_my_list(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    # Aqui o SQLAlchemy traz o objeto completo, incluindo o novo campo 'rating'
    games = (
        db.query(GameTable)
        .filter(GameTable.owner_username == current_user.username)
        .all()
    )
    return templates.TemplateResponse(
        "my_list.html", {"request": request, "games": games}
    )
