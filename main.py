import os
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated
from sqlalchemy import func as sqlfunc

import jwt
import requests
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware

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
from dotenv import load_dotenv

load_dotenv()

from database import ForumComment, ForumPost, GameTable, GameView, UserCreate, UserTable, get_db, SessionLocal

# --- CONFIGURAÇÕES ---
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
API_KEY = "35feb255f6ac4b88a3ed5cee84341acd"
BASE_URL = "https://api.rawg.io/api/games"

# --- CHAVES DE API DE PLATAFORMAS (carregadas do .env) ---
STEAM_API_KEY    = os.getenv("STEAM_API_KEY", "")
OPENXBL_API_KEY  = os.getenv("OPENXBL_API_KEY", "")

app = FastAPI(strict_slashes=False)
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET", secrets.token_urlsafe(32)))



BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)
password_hash = PasswordHash.recommended()
DUMMY_HASH = password_hash.hash("dummypassword")


# --- EVENTO DE STARTUP: garante usuário admin padrão ---
@app.on_event("startup")
async def create_default_admin():
    """Cria o usuário admin padrão (admin/admin) na primeira inicialização."""
    db = SessionLocal()
    try:
        existing = db.query(UserTable).filter(UserTable.username == "admin").first()
        if not existing:
            admin_user = UserTable(
                username="admin",
                email="admin@mygamelist.local",
                full_name="Administrador",
                hashed_password=password_hash.hash("admin"),
                disabled=False,
                is_admin=True,
            )
            db.add(admin_user)
            db.commit()
            print("✅ Usuário admin criado: login=admin / senha=admin")
        elif not existing.is_admin:
            existing.is_admin = True
            db.commit()
            print("✅ Usuário 'admin' promovido a administrador.")
        else:
            print("ℹ️  Usuário admin já existe.")
    except Exception as exc:
        print(f"⚠️  Erro ao criar admin padrão: {exc}")
    finally:
        db.close()


# --- CONFIGURAÇÃO GOOGLE OAUTH ---
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")

oauth = OAuth()
oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)


# --- MODELOS PYDANTIC ---
class Token(BaseModel):
    access_token: str
    token_type: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    date_of_birth: str | None = None
    profile_bio: str | None = None
    disabled: bool | None = None
    is_admin: bool = False
    xbox_gamertag: str | None = None
    psn_id: str | None = None
    steam_id: str | None = None
    nintendo_id: str | None = None
    ra_username: str | None = None


class SyncXboxRequest(BaseModel):
    gamertag: str


class SyncPsnRequest(BaseModel):
    psn_id: str


class SyncSteamRequest(BaseModel):
    steam_id: str


class SyncNintendoRequest(BaseModel):
    nintendo_id: str


class SyncRetroRequest(BaseModel):
    ra_username: str


class GameTagsUpdate(BaseModel):
    tags: str | None = None



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
    is_anonymous: bool = False


class ForumCommentCreate(BaseModel):
    content: str
    rating: int = 0  # 0-5 estrelas
    is_anonymous: bool = False


class GameNotesUpdate(BaseModel):
    notes: str | None = None


class GameCategoryUpdate(BaseModel):
    category: str | None = None


class GameStatusUpdate(BaseModel):
    status: str | None = None


class GamePlatformUpdate(BaseModel):
    platform: str | None = None


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


async def get_current_admin(
    current_user: Annotated[UserTable, Depends(get_current_active_user)],
):
    """Exige que o usuário autenticado seja administrador."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: área restrita a administradores.",
        )
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


@app.get("/auth/google/login")
async def login_via_google(request: Request):
    """Inicia o fluxo de login OAuth do Google."""
    redirect_uri = GOOGLE_REDIRECT_URI
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/google/callback")
async def auth_via_google_callback(request: Request, db: Session = Depends(get_db)):
    """Recebe o callback do Google e processa o usuário."""
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Erro na autenticação do Google: {str(e)}")

    user_info = token.get('userinfo')
    if not user_info:
        raise HTTPException(status_code=400, detail="Não foi possível obter as informações do usuário")

    email = user_info.get("email")
    name = user_info.get("name")
    
    # Verifica se usuário já existe
    user = db.query(UserTable).filter(UserTable.email == email).first()
    
    if not user:
        # Cria novo usuário baseando-se no e-mail
        base_username = email.split('@')[0]
        username = base_username
        
        # Resolve conflitos de username
        counter = 1
        while db.query(UserTable).filter(UserTable.username == username).first():
            username = f"{base_username}{counter}"
            counter += 1
            
        user = UserTable(
            username=username,
            email=email,
            full_name=name,
            hashed_password=get_password_hash(secrets.token_urlsafe(16)), # Senha forte inacessível
            disabled=False
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    # Emite o JWT padrão e gera a sessão
    access_token = create_access_token(data={"sub": user.username})
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
      <head>
        <title>Autenticando...</title>
      </head>
      <body style="background: #050816; color: #fff; font-family: sans-serif; display: grid; place-items: center; height: 100vh; margin: 0;">
        <h2>Completando login...</h2>
        <script>
          localStorage.setItem("access_token", "{access_token}");
          window.location.href = "/dashboard";
        </script>
      </body>
    </html>
    """
    
    response = HTMLResponse(content=html_content)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=False,
        max_age=1800,
        samesite="lax",
    )
    return response


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


@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse(request=request, name="forgot_password.html", context={})


@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request):
    return templates.TemplateResponse(request=request, name="reset_password.html", context={})


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(
    request: Request,
    search: str | None = None,
    genre: str | None = None,
    tag: str | None = None,
    platform: str | None = None
):
    games = []
    if search or genre or tag or platform:
        url = f"{BASE_URL}?key={API_KEY}"
        if search:
            url += f"&search={search}"
        if genre:
            url += f"&genres={genre}"
        if tag:
            url += f"&tags={tag}"
        if platform:
            url += f"&platforms={platform}"
        resp = requests.get(url)
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


@app.get("/em-alta", response_class=HTMLResponse)
async def em_alta_page(request: Request):
    return templates.TemplateResponse(request=request, name="em_alta.html", context={})


@app.get("/home-admin", response_class=RedirectResponse)
async def redirect_home_admin():
    return RedirectResponse(url="/admin")


@app.get("/home-adm", response_class=RedirectResponse)
async def redirect_home_adm():
    return RedirectResponse(url="/admin")


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
        is_admin=current_user.is_admin or False,
        xbox_gamertag=current_user.xbox_gamertag,
        psn_id=current_user.psn_id,
        steam_id=current_user.steam_id,
        nintendo_id=current_user.nintendo_id,
        ra_username=current_user.ra_username,
    )


@app.post("/api/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    user = db.query(UserTable).filter(UserTable.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="E-mail não encontrado.")

    # Gera um token JWT com expiração de 30 minutos e flag "reset"
    token_data = {"sub": user.email, "type": "reset"}
    reset_token = create_access_token(data=token_data, expires_delta=timedelta(minutes=30))

    base_url = str(request.base_url).rstrip("/")
    reset_link = f"{base_url}/reset-password?token={reset_token}"
    load_dotenv()
    
    smtp_email = os.getenv("SMTP_EMAIL")
    smtp_password = os.getenv("SMTP_PASSWORD")

    if not smtp_email or not smtp_password:
        raise HTTPException(status_code=500, detail="Servidor não configurado para envio de e-mails (SMTP_EMAIL e SMTP_PASSWORD vazios).")

    try:
        msg = MIMEText(f"Olá,\n\nVocê solicitou a redefinição de sua senha. Clique no link abaixo para criar uma nova senha:\n{reset_link}\n\nEste link expira em 30 minutos.\n\nSe você não solicitou, apenas ignore este e-mail.")
        msg['Subject'] = "Recuperação de Senha - MyGameList"
        msg['From'] = f"MyGameList <{smtp_email}>"
        msg['To'] = user.email

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(smtp_email, smtp_password)
            server.send_message(msg)
    except Exception as e:
        print(f"Erro ao enviar e-mail SMTP: {e}")
        raise HTTPException(status_code=500, detail="Ocorreu um erro ao tentar enviar o e-mail.")

    return {"message": "Se o e-mail estiver cadastrado, um link de recuperação foi enviado."}


@app.post("/api/reset-password")
async def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    try:
        token_data = jwt.decode(payload.token, SECRET_KEY, algorithms=[ALGORITHM])
        if token_data.get("type") != "reset":
            raise InvalidTokenError()
        email = token_data.get("sub")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Token inválido ou expirado.")

    user = db.query(UserTable).filter(UserTable.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="A senha deve ter no mínimo 6 caracteres.")

    user.hashed_password = get_password_hash(payload.new_password)
    db.commit()

    return {"message": "Senha redefinida com sucesso."}


@app.post("/add-to-catalog/")
async def add_game(
    game_id: int = Form(...),
    title: str = Form(...),
    image: str = Form(...),
    status: str | None = Form(None),
    platform: str | None = Form(None),
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
        status=status,
        platform=platform,
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
        return {"status": "success", "message": "Jogo removido"}
    raise HTTPException(status_code=404, detail="Jogo não encontrado na sua lista")


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
async def admin_list_users(
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_admin),
):
    users = db.query(UserTable).all()
    return [
        {
            "usuario": u.username,
            "nome": u.full_name or "",
            "email": u.email or "",
            "tipo": "admin" if u.is_admin else "user",
            "ativo": not u.disabled,
            "is_admin": u.is_admin or False,
        }
        for u in users
    ]


@app.post("/admin/cadastro")
async def admin_create_user(
    payload: AdminUserCreate,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_admin),
):
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
        is_admin=(payload.tipo == "admin"),
    )
    db.add(new_user)
    db.commit()
    return {"message": "Usuário criado com sucesso"}


@app.put("/admin/usuarios/{username}")
async def admin_update_user(
    username: str,
    payload: AdminUserUpdate,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_admin),
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
    username: str,
    payload: AdminStatusUpdate,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_admin),
):
    user = db.query(UserTable).filter(UserTable.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    user.disabled = not payload.ativo
    db.commit()
    return {"message": "Status atualizado"}


@app.delete("/admin/usuarios/{username}")
async def admin_delete_user(
    username: str,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_admin),
):
    user = db.query(UserTable).filter(UserTable.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    # Não permite excluir a si mesmo
    if user.username == current_user.username:
        raise HTTPException(status_code=400, detail="Não é possível excluir sua própria conta")
    db.delete(user)
    db.commit()
    return {"message": "Usuário excluído"}


class AdminToggleAdmin(BaseModel):
    is_admin: bool


@app.patch("/admin/usuarios/{username}/toggle-admin")
async def admin_toggle_admin(
    username: str,
    payload: AdminToggleAdmin,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_admin),
):
    user = db.query(UserTable).filter(UserTable.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    # Não permite rebaixar a si mesmo
    if user.username == current_user.username and not payload.is_admin:
        raise HTTPException(status_code=400, detail="Não é possível remover seus próprios privilégios de admin")
    user.is_admin = payload.is_admin
    db.commit()
    action = "promovido a administrador" if payload.is_admin else "removido de administrador"
    return {"message": f"Usuário {username} {action}."}


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN — Fórum (moderação de posts)
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/admin/forum/posts")
async def admin_list_forum_posts(
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_admin),
):
    """Lista todos os posts do fórum para moderação."""
    posts = db.query(ForumPost).order_by(ForumPost.created_at.desc()).all()
    return [
        {
            "id":             p.id,
            "content":        p.content[:200] + ("..." if len(p.content) > 200 else ""),
            "author_username": p.author_username,
            "is_anonymous":   p.is_anonymous,
            "likes":          p.likes,
            "created_at":     p.created_at.isoformat() if p.created_at else None,
            "comment_count":  db.query(ForumComment).filter(ForumComment.post_id == p.id).count(),
        }
        for p in posts
    ]


@app.delete("/admin/forum/posts/{post_id}")
async def admin_delete_forum_post(
    post_id: int,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_admin),
):
    """Exclui um post do fórum e todos os seus comentários."""
    post = db.query(ForumPost).filter(ForumPost.id == post_id).first()
    if not post:
        raise HTTPException(status_code=404, detail="Post não encontrado")
    db.query(ForumComment).filter(ForumComment.post_id == post_id).delete()
    db.delete(post)
    db.commit()
    return {"message": "Post excluído com sucesso"}


class PromoteAdminRequest(BaseModel):
    codigo: str


@app.post("/api/admin/promote-self")
async def promote_self_to_admin(
    payload: PromoteAdminRequest,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    """Permite que um usuário se torne admin informando o código mestre.
    Útil para configurar o primeiro admin do sistema."""
    ADMIN_MASTER_CODE = "mgl-admin-2025"
    if payload.codigo != ADMIN_MASTER_CODE:
        raise HTTPException(status_code=403, detail="Código mestre inválido")
    current_user.is_admin = True
    db.commit()
    return {"message": f"Parabéns, {current_user.username} agora é administrador!"}


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
        # Se anônimo, oculta o nome do autor
        if p.is_anonymous:
            display_name = "Anônimo"
        else:
            display_name = author.full_name or p.author_username if author else p.author_username
        result.append({
            "id": p.id,
            "content": p.content,
            "author_username": p.author_username if not p.is_anonymous else None,
            "author_name": display_name,
            "created_at": p.created_at.isoformat() if p.created_at else None,
            "likes": p.likes,
            "comment_count": count,
            "is_anonymous": p.is_anonymous,
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
    post = ForumPost(
        content=payload.content.strip(),
        author_username=current_user.username,
        is_anonymous=payload.is_anonymous,
    )
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
        # Se anônimo, oculta o nome do autor
        if c.is_anonymous:
            display_name = "Anônimo"
        else:
            display_name = author.full_name or c.author_username if author else c.author_username
        result.append({
            "id": c.id,
            "content": c.content,
            "author_username": c.author_username if not c.is_anonymous else None,
            "author_name": display_name,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "likes": c.likes,
            "rating": c.rating or 0,
            "is_anonymous": c.is_anonymous,
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
        is_anonymous=payload.is_anonymous,
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


@app.patch("/api/my-list/{game_id}/category")
async def update_game_category(
    game_id: int,
    payload: GameCategoryUpdate,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    game = db.query(GameTable).filter(
        GameTable.id == game_id,
        GameTable.owner_username == current_user.username,
    ).first()
    if not game:
        raise HTTPException(status_code=404, detail="Jogo não encontrado na sua lista")
    game.category = payload.category
    db.commit()
    return {"message": "Categoria salva!", "category": game.category}


@app.patch("/api/my-list/{game_id}/status")
async def update_game_status(
    game_id: int,
    payload: GameStatusUpdate,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    game = db.query(GameTable).filter(
        GameTable.id == game_id,
        GameTable.owner_username == current_user.username,
    ).first()
    if not game:
        raise HTTPException(status_code=404, detail="Jogo não encontrado na sua lista")
    game.status = payload.status
    db.commit()
    return {"message": "Status salvo!", "status": game.status}


@app.patch("/api/my-list/{game_id}/platform")
async def update_game_platform(
    game_id: int,
    payload: GamePlatformUpdate,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    game = db.query(GameTable).filter(
        GameTable.id == game_id,
        GameTable.owner_username == current_user.username,
    ).first()
    if not game:
        raise HTTPException(status_code=404, detail="Jogo não encontrado na sua lista")
    game.platform = payload.platform
    db.commit()
    return {"message": "Plataforma salva!", "platform": game.platform}


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


# ─────────────────────────────────────────────────────────────────────────────
# INSIGHTS — Trending & Correlações
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/insights/trending-platform")
async def insights_trending_platform(
    period: str = "week",
    db: Session = Depends(get_db),
):
    """Jogos mais adicionados e avaliados na plataforma no período (week|month)."""
    # Mais adicionados — popularidade acumulada
    added_rows = (
        db.query(
            GameTable.game_api_id,
            GameTable.title,
            GameTable.image_url,
            sqlfunc.count(GameTable.owner_username).label("count"),
        )
        .group_by(GameTable.game_api_id, GameTable.title, GameTable.image_url)
        .order_by(sqlfunc.count(GameTable.owner_username).desc())
        .limit(12)
        .all()
    )

    # Mais bem avaliados na plataforma
    rated_rows = (
        db.query(
            GameTable.game_api_id,
            GameTable.title,
            GameTable.image_url,
            sqlfunc.avg(GameTable.rating).label("avg_rating"),
            sqlfunc.count(GameTable.owner_username).label("voters"),
        )
        .filter(GameTable.rating > 0)
        .group_by(GameTable.game_api_id, GameTable.title, GameTable.image_url)
        .order_by(sqlfunc.avg(GameTable.rating).desc())
        .limit(12)
        .all()
    )

    return {
        "period": period,
        "most_added": [
            {"game_api_id": r.game_api_id, "title": r.title, "image_url": r.image_url, "count": r.count}
            for r in added_rows
        ],
        "best_rated": [
            {"game_api_id": r.game_api_id, "title": r.title, "image_url": r.image_url,
             "avg_rating": round(float(r.avg_rating), 2), "voters": r.voters}
            for r in rated_rows
        ],
        "most_users": [
            {"game_api_id": r.game_api_id, "title": r.title, "image_url": r.image_url, "count": r.count}
            for r in added_rows
        ],
    }


@app.get("/api/insights/my-insights")
async def insights_my_insights(
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    """Correlaciona os jogos do usuário com os trending da plataforma."""
    my_games = (
        db.query(GameTable)
        .filter(GameTable.owner_username == current_user.username)
        .all()
    )

    # IDs dos jogos trending na plataforma
    trending_rows = (
        db.query(
            GameTable.game_api_id,
            sqlfunc.count(GameTable.owner_username).label("count"),
        )
        .group_by(GameTable.game_api_id)
        .order_by(sqlfunc.count(GameTable.owner_username).desc())
        .limit(50)
        .all()
    )
    trending_ids = {r.game_api_id: r.count for r in trending_rows}

    my_games_data = []
    for g in my_games:
        my_games_data.append({
            "id": g.id,
            "game_api_id": g.game_api_id,
            "title": g.title,
            "image_url": g.image_url,
            "rating": g.rating or 0,
            "status": g.status,
            "platform": g.platform,
            "is_trending": g.game_api_id in trending_ids,
            "trending_count": trending_ids.get(g.game_api_id, 0),
        })

    # Ordena: trending primeiro, depois por rating
    my_games_data.sort(key=lambda x: (-x["is_trending"], -x["trending_count"], -x["rating"]))

    return {
        "username": current_user.username,
        "total_games": len(my_games_data),
        "trending_overlap": sum(1 for g in my_games_data if g["is_trending"]),
        "games": my_games_data[:20],
    }


@app.get("/api/insights/trending-external")
async def insights_trending_external(platform: str = "all"):
    """Jogos em alta globalmente via RAWG, filtrados por plataforma."""
    platform_ids: dict = {
        "pc":          "4",
        "playstation": "18,187",
        "xbox":        "1,186",
        "mobile":      "3,21",
    }
    today   = datetime.utcnow().strftime("%Y-%m-%d")
    six_ago = (datetime.utcnow() - timedelta(days=180)).strftime("%Y-%m-%d")

    url = (
        f"{BASE_URL}?key={API_KEY}"
        f"&ordering=-added&page_size=20"
        f"&dates={six_ago},{today}"
    )
    if platform != "all" and platform in platform_ids:
        url += f"&platforms={platform_ids[platform]}"

    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            return [
                {
                    "game_api_id": g.get("id"),
                    "title":       g.get("name"),
                    "image_url":   g.get("background_image"),
                    "rating":      g.get("rating"),
                    "metacritic":  g.get("metacritic"),
                    "added":       g.get("added"),
                    "released":    g.get("released"),
                    "platforms":   [p["platform"]["name"] for p in (g.get("platforms") or [])[:3]],
                    "genres":      [gr["name"] for gr in (g.get("genres") or [])[:3]],
                }
                for g in resp.json().get("results", [])
            ]
    except Exception as exc:
        print(f"RAWG trending-external error: {exc}")
    return []


# Inclui notes e tags no endpoint de lista JSON usada pelo perfil
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
            "category": g.category,
            "status": g.status,
            "platform": g.platform,
            "tags": g.tags,
        }
        for g in games
    ]


@app.patch("/api/my-list/{game_id}/tags")
async def update_game_tags(
    game_id: int,
    payload: GameTagsUpdate,
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

    game.tags = payload.tags
    db.commit()
    return {"message": "Tags atualizadas!", "tags": payload.tags}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS — Integrações com APIs de plataformas
# ─────────────────────────────────────────────────────────────────────────────

def _fetch_steam_games(steam_id: str) -> dict:
    """
    Busca a lista de jogos do usuário via Steam Web API (IPlayerService/GetOwnedGames).
    Retorna dict com 'games' (lista), 'games_count' e 'playtime_hours'.
    Levanta ValueError se a API key não estiver configurada ou o perfil for privado.
    """
    if not STEAM_API_KEY:
        raise ValueError("STEAM_API_KEY não configurada no servidor. Adicione ao arquivo .env.")

    url = (
        "https://api.steampowered.com/IPlayerService/GetOwnedGames/v1/"
        f"?key={STEAM_API_KEY}&steamid={steam_id}"
        "&include_appinfo=1&include_played_free_games=1&format=json"
    )
    try:
        resp = requests.get(url, timeout=10)
    except requests.exceptions.Timeout:
        raise ValueError("A Steam API demorou muito para responder. Tente novamente.")
    except requests.exceptions.RequestException as exc:
        raise ValueError(f"Erro de conexão com a Steam API: {exc}")

    if resp.status_code == 401:
        raise ValueError("Steam API Key inválida ou sem permissão.")
    if resp.status_code != 200:
        raise ValueError(f"Steam API retornou status {resp.status_code}.")

    data = resp.json().get("response", {})
    raw_games = data.get("games")

    if raw_games is None:
        # Perfil privado ou SteamID inválido
        raise ValueError(
            "Não foi possível obter os jogos. O perfil Steam pode estar privado ou o SteamID é inválido."
        )

    # Ordena pelo tempo de jogo (mais jogados primeiro) e pega os top 30
    raw_games.sort(key=lambda g: g.get("playtime_forever", 0), reverse=True)
    top_games = raw_games[:30]

    total_playtime_minutes = sum(g.get("playtime_forever", 0) for g in raw_games)

    games_out = []
    for g in top_games:
        appid = g.get("appid")
        name  = g.get("name") or f"App {appid}"
        image = f"https://cdn.akamai.steamstatic.com/steam/apps/{appid}/header.jpg"
        hours = round(g.get("playtime_forever", 0) / 60, 1)
        games_out.append({"appid": appid, "title": name, "image_url": image, "hours": hours})

    return {
        "games": games_out,
        "games_count": len(raw_games),
        "playtime_hours": round(total_playtime_minutes / 60, 1),
    }


def _fetch_xbox_profile(gamertag: str) -> dict:
    """
    Busca o perfil de um Gamertag via OpenXBL (xbl.io).
    Retorna dict com 'gamerscore', 'achievements_count', 'xuid', 'gamertag'.
    Levanta ValueError se a API key não estiver configurada ou o gamertag não for encontrado.
    """
    if not OPENXBL_API_KEY:
        raise ValueError("OPENXBL_API_KEY não configurada no servidor. Adicione ao arquivo .env.")

    headers = {
        "X-Authorization": OPENXBL_API_KEY,
        "Accept": "application/json",
        "Accept-Language": "pt-BR",
    }

    # Busca o XUID do gamertag via endpoint de busca
    search_url = f"https://xbl.io/api/v2/friends/search?gt={requests.utils.quote(gamertag)}"
    try:
        search_resp = requests.get(search_url, headers=headers, timeout=10)
    except requests.exceptions.Timeout:
        raise ValueError("OpenXBL API demorou muito. Tente novamente.")
    except requests.exceptions.RequestException as exc:
        raise ValueError(f"Erro de conexão com OpenXBL: {exc}")

    if search_resp.status_code == 401:
        raise ValueError("OpenXBL API Key inválida. Verifique a chave em xbl.io.")
    if search_resp.status_code == 429:
        raise ValueError("Limite de requisições OpenXBL atingido (150/hora). Tente mais tarde.")
    if search_resp.status_code == 404:
        raise ValueError(f"Gamertag '{gamertag}' não encontrado no Xbox Live.")
    if search_resp.status_code != 200:
        raise ValueError(f"OpenXBL retornou status {search_resp.status_code}.")

    search_data = search_resp.json()
    people = search_data.get("people", [])
    if not people:
        raise ValueError(f"Gamertag '{gamertag}' não encontrado no Xbox Live.")

    person       = people[0]
    xuid         = person.get("xuid", "")
    gamerscore   = person.get("gamerScore", 0)
    display_name = person.get("gamertag", gamertag)

    # Busca contagem de achievements via endpoint de estatísticas do player
    achievements_count = 0
    try:
        stats_url  = f"https://xbl.io/api/v2/achievements/player/{xuid}"
        stats_resp = requests.get(stats_url, headers=headers, timeout=10)
        if stats_resp.status_code == 200:
            ach_data = stats_resp.json()
            # O endpoint retorna lista de achievements; conta os desbloqueados
            achievements_list = ach_data.get("achievements", [])
            achievements_count = sum(
                1 for a in achievements_list if a.get("progressState") == "Achieved"
            )
    except Exception:
        pass  # Falha silenciosa — gamerscore já foi obtido

    return {
        "xuid":               xuid,
        "gamertag":           display_name,
        "gamerscore":         int(gamerscore) if gamerscore else 0,
        "achievements_count": achievements_count,
    }


def _fetch_psn_top_games(db: Session) -> list:
    """
    Busca os jogos de PlayStation mais populares combinando duas fontes reais:
    1. Placar interno do site: jogos PS mais adicionados pelos usuários
    2. RAWG API: top jogos PlayStation por rating global

    Retorna lista unificada com no máximo 10 jogos, priorizando os do site.
    """
    # ── Fonte 1: placar interno do site ──────────────────────────────────────
    # Jogos catalogados como PlayStation (qualquer variação) mais adicionados
    ps_keywords = ["%PlayStation%", "%PS5%", "%PS4%", "%PS3%"]
    from sqlalchemy import or_
    internal_rows = (
        db.query(
            GameTable.game_api_id,
            GameTable.title,
            GameTable.image_url,
            sqlfunc.count(GameTable.owner_username).label("popularity"),
        )
        .filter(
            or_(*[GameTable.platform.ilike(kw) for kw in ps_keywords])
        )
        .group_by(GameTable.game_api_id, GameTable.title, GameTable.image_url)
        .order_by(sqlfunc.count(GameTable.owner_username).desc())
        .limit(6)
        .all()
    )

    internal_games = [
        {
            "game_api_id": r.game_api_id,
            "title":       r.title,
            "image_url":   r.image_url,
            "popularity":  r.popularity,
            "source":      "site",
        }
        for r in internal_rows
    ]

    # IDs já incluídos (para evitar duplicatas)
    included_ids = {g["game_api_id"] for g in internal_games}

    # ── Fonte 2: RAWG — top jogos PlayStation por rating ─────────────────────
    # Plataformas PlayStation no RAWG: 18=PS4, 187=PS5, 17=PS3
    rawg_games = []
    try:
        rawg_url = (
            f"{BASE_URL}?key={API_KEY}"
            "&platforms=18,187&ordering=-rating&page_size=10"
            "&metacritic=80,100"
        )
        rawg_resp = requests.get(rawg_url, timeout=8)
        if rawg_resp.status_code == 200:
            for g in rawg_resp.json().get("results", []):
                gid = g.get("id")
                if gid and gid not in included_ids:
                    rawg_games.append({
                        "game_api_id": gid,
                        "title":       g.get("name"),
                        "image_url":   g.get("background_image"),
                        "popularity":  g.get("added", 0),
                        "source":      "rawg",
                    })
                    included_ids.add(gid)
                if len(rawg_games) >= 6:
                    break
    except Exception:
        pass  # Fallback silencioso — dados internos ainda serão usados

    # Combina: internos primeiro (mais relevantes para o site), depois RAWG
    combined = internal_games + rawg_games
    return combined[:10]


# ─────────────────────────────────────────────────────────────────────────────
# LOOKUP PÚBLICO — Steam
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/steam/lookup/{steam_id}")
async def steam_lookup(steam_id: str):
    """
    Endpoint público para verificar se um SteamID64 é válido e o perfil é acessível.
    Retorna resumo básico do perfil: total de jogos, horas totais e top 5 jogos.
    """
    try:
        data = _fetch_steam_games(steam_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    top5 = [{"title": g["title"], "hours": g["hours"]} for g in data["games"][:5]]
    return {
        "steam_id":     steam_id,
        "games_count":  data["games_count"],
        "playtime_hours": data["playtime_hours"],
        "top_games":    top5,
        "valid":        True,
    }


# ─────────────────────────────────────────────────────────────────────────────
# LOOKUP PÚBLICO — Xbox
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/xbox/lookup/{gamertag}")
async def xbox_lookup(gamertag: str):
    """
    Endpoint público para verificar se um Gamertag existe no Xbox Live.
    Retorna gamerscore e XUID do jogador.
    """
    try:
        data = _fetch_xbox_profile(gamertag)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "gamertag":           data["gamertag"],
        "xuid":               data["xuid"],
        "gamerscore":         data["gamerscore"],
        "achievements_count": data["achievements_count"],
        "valid":              True,
    }


# ─────────────────────────────────────────────────────────────────────────────
# SYNC — Xbox (via OpenXBL)
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/profile/sync-xbox")
async def sync_xbox(
    payload: SyncXboxRequest,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    """
    Sincroniza o Gamertag Xbox do usuário.
    Se OPENXBL_API_KEY estiver configurada, busca dados reais via OpenXBL.
    Caso contrário, retorna erro solicitando configuração da chave.
    """
    current_user.xbox_gamertag = payload.gamertag
    db.commit()

    # --- Tentativa de integração real via OpenXBL ---
    xbox_data = None
    api_error = None
    if OPENXBL_API_KEY:
        try:
            xbox_data = _fetch_xbox_profile(payload.gamertag)
        except ValueError as exc:
            api_error = str(exc)

    if xbox_data:
        # Sucesso: retorna dados reais
        return {
            "status":             "success",
            "message":            f"Xbox Live sincronizado! Gamertag verificado com dados reais.",
            "source":             "openxbl",
            "gamertag":           xbox_data["gamertag"],
            "xuid":               xbox_data["xuid"],
            "gamerscore":         xbox_data["gamerscore"],
            "achievements_count": xbox_data["achievements_count"],
        }
    else:
        # Sem chave ou erro: salva o gamertag mas informa o motivo
        detail = api_error or "OPENXBL_API_KEY não configurada. Adicione ao .env para dados reais."
        return {
            "status":             "partial",
            "message":            f"Gamertag '{payload.gamertag}' salvo. {detail}",
            "source":             "none",
            "gamertag":           payload.gamertag,
            "gamerscore":         None,
            "achievements_count": None,
        }


@app.post("/api/profile/disconnect-xbox")
async def disconnect_xbox(
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    current_user.xbox_gamertag = None
    db.commit()
    return {"status": "success", "message": "Xbox Live desconectado."}


# ─────────────────────────────────────────────────────────────────────────────
# SYNC — PSN
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/profile/sync-psn")
async def sync_psn(
    payload: SyncPsnRequest,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    """
    Sincroniza a conta PSN do usuário.
    Como a PSN não possui API pública oficial, importa os jogos PlayStation
    mais populares combinando duas fontes reais:
      1. Placar interno do site (jogos PS mais adicionados pelos usuários)
      2. RAWG API (top jogos PlayStation por rating global com Metacritic 80+)
    """
    current_user.psn_id = payload.psn_id
    db.commit()

    # Busca jogos reais: placar interno + RAWG PlayStation
    top_ps_games = _fetch_psn_top_games(db)

    # Importa os jogos para a lista do usuário (evita duplicatas)
    imported_count = 0
    for g in top_ps_games:
        existing = db.query(GameTable).filter(
            GameTable.owner_username == current_user.username,
            GameTable.game_api_id == g["game_api_id"]
        ).first()
        if not existing:
            # Define plataforma com base na fonte
            platform = "PlayStation" if g["source"] == "site" else "PlayStation 5"
            new_game = GameTable(
                game_api_id=g["game_api_id"],
                title=g["title"],
                image_url=g["image_url"],
                owner_username=current_user.username,
                platform=platform,
                status="Pretendo Jogar",
                category="",
                notes=(
                    f"Importado via PSN Sync | "
                    f"{'Popular no site' if g['source'] == 'site' else 'Top PlayStation (RAWG)'}"
                ),
            )
            db.add(new_game)
            imported_count += 1

    db.commit()

    # Placar interno: total de jogos PS no site
    from sqlalchemy import or_
    ps_keywords = ["%PlayStation%", "%PS5%", "%PS4%", "%PS3%"]
    total_ps_on_site = (
        db.query(sqlfunc.count(GameTable.id))
        .filter(or_(*[GameTable.platform.ilike(kw) for kw in ps_keywords]))
        .scalar()
    ) or 0

    # Usuários únicos com jogos PS
    ps_users = (
        db.query(sqlfunc.count(sqlfunc.distinct(GameTable.owner_username)))
        .filter(or_(*[GameTable.platform.ilike(kw) for kw in ps_keywords]))
        .scalar()
    ) or 0

    return {
        "status":            "success",
        "message":           f"PSN sincronizada! {imported_count} jogo(s) PlayStation adicionado(s) à sua lista.",
        "source":            "internal_ranking_rawg",
        "psn_id":           payload.psn_id,
        "imported_count":   imported_count,
        "top_ps_games":     [{"title": g["title"], "source": g["source"]} for g in top_ps_games[:5]],
        "site_ps_stats": {
            "total_ps_entries": total_ps_on_site,
            "ps_players":       ps_users,
        },
    }


@app.post("/api/profile/disconnect-psn")
async def disconnect_psn(
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    current_user.psn_id = None
    db.commit()
    return {"status": "success", "message": "PSN desconectada."}


# ─────────────────────────────────────────────────────────────────────────────
# SYNC — Steam (via Steam Web API Oficial)
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/profile/sync-steam")
async def sync_steam(
    payload: SyncSteamRequest,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    """
    Sincroniza a biblioteca Steam do usuário via Steam Web API oficial.
    Busca os jogos reais com horas de jogo e importa os top 30 mais jogados.
    Requer STEAM_API_KEY no .env e perfil Steam público.
    """
    current_user.steam_id = payload.steam_id
    db.commit()

    # --- Integração real com Steam Web API ---
    if not STEAM_API_KEY:
        return {
            "status":        "partial",
            "message":       "Steam ID salvo. Configure STEAM_API_KEY no .env para importar jogos reais.",
            "source":        "none",
            "steam_id":      payload.steam_id,
            "games_count":   None,
            "playtime_hours": None,
            "imported_count": 0,
        }

    try:
        steam_data = _fetch_steam_games(payload.steam_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Faz cruzamento com RAWG para obter IDs do catálogo interno
    # Usamos o appid da Steam como game_api_id para evitar colisão de IDs
    # (negamos o appid para distinguir de IDs do RAWG)
    imported_count = 0
    top_games_summary = []

    for g in steam_data["games"]:
        # Usa appid negativo como identificador único no nosso catálogo
        internal_id = -(g["appid"])

        existing = db.query(GameTable).filter(
            GameTable.owner_username == current_user.username,
            GameTable.game_api_id == internal_id
        ).first()

        hours = g["hours"]
        status_str = "Zerado" if hours > 20 else ("Jogando" if hours > 0 else "Pretendo Jogar")

        if not existing:
            new_game = GameTable(
                game_api_id=internal_id,
                title=g["title"],
                image_url=g["image_url"],
                owner_username=current_user.username,
                platform="PC (Steam)",
                status=status_str,
                category="",
                notes=f"Steam AppID: {g['appid']} | {hours}h jogadas",
            )
            db.add(new_game)
            imported_count += 1
        else:
            # Atualiza horas nas notas mesmo se jogo já existir
            existing.notes = f"Steam AppID: {g['appid']} | {hours}h jogadas"

        top_games_summary.append({"title": g["title"], "hours": hours})

    db.commit()

    return {
        "status":         "success",
        "message":        f"Steam sincronizado! {imported_count} jogo(s) novo(s) importado(s) de {steam_data['games_count']} na biblioteca.",
        "source":         "steam_web_api",
        "steam_id":       payload.steam_id,
        "games_count":    steam_data["games_count"],
        "playtime_hours": steam_data["playtime_hours"],
        "imported_count": imported_count,
        "top_games":      top_games_summary[:10],
    }


@app.post("/api/profile/disconnect-steam")
async def disconnect_steam(
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    current_user.steam_id = None
    db.commit()
    return {"status": "success", "message": "Steam desconectado."}


@app.post("/api/profile/sync-nintendo")
async def sync_nintendo(
    payload: SyncNintendoRequest,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    current_user.nintendo_id = payload.nintendo_id
    db.commit()

    # Mock games to import
    nintendo_games = [
        {"game_api_id": 22501, "title": "The Legend of Zelda: Breath of the Wild", "image_url": "https://media.rawg.io/media/games/283/283e7e473506c58c959f4a578b8146b2.jpg"},
        {"game_api_id": 50738, "title": "Super Mario Odyssey", "image_url": "https://media.rawg.io/media/games/212/212f458e0b04e03d7e5d8c47b56a588b.jpg"},
        {"game_api_id": 41494, "title": "Animal Crossing: New Horizons", "image_url": "https://media.rawg.io/media/games/a71/a71a067a1f574d75ee58ea47f5b1287c.jpg"},
    ]

    imported_count = 0
    for g in nintendo_games:
        existing = db.query(GameTable).filter(
            GameTable.owner_username == current_user.username,
            GameTable.game_api_id == g["game_api_id"]
        ).first()
        if not existing:
            new_game = GameTable(
                game_api_id=g["game_api_id"],
                title=g["title"],
                image_url=g["image_url"],
                owner_username=current_user.username,
                platform="Nintendo Switch",
                status="Jogando",
                category="Aventura",
            )
            db.add(new_game)
            imported_count += 1

    db.commit()
    return {
        "status": "success",
        "message": f"Conta Nintendo sincronizada! {imported_count} jogo(s) importado(s).",
        "nintendo_id": payload.nintendo_id,
        "nintendo_playtime": 450,
        "games_count": 14,
    }


@app.post("/api/profile/disconnect-nintendo")
async def disconnect_nintendo(
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    current_user.nintendo_id = None
    db.commit()
    return {"status": "success", "message": "Conta Nintendo desconectada."}


@app.post("/api/profile/sync-retroachievements")
async def sync_retroachievements(
    payload: SyncRetroRequest,
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    current_user.ra_username = payload.ra_username
    db.commit()

    # Mock games to import
    ra_games = [
        {"game_api_id": 52362, "title": "Super Mario World", "image_url": "https://media.rawg.io/media/games/0a5/0a57e4e1e07b8b4200778c47b56a588b.jpg"},
        {"game_api_id": 53580, "title": "Sonic the Hedgehog", "image_url": "https://media.rawg.io/media/games/b2c/b2c86bd7e411c40b1df8e6b1287c5c0c.jpg"},
        {"game_api_id": 53896, "title": "Chrono Trigger", "image_url": "https://media.rawg.io/media/games/33d/33d77e4b52fe0e4c6c061801f4c718b9.jpg"},
    ]

    imported_count = 0
    for g in ra_games:
        existing = db.query(GameTable).filter(
            GameTable.owner_username == current_user.username,
            GameTable.game_api_id == g["game_api_id"]
        ).first()
        if not existing:
            new_game = GameTable(
                game_api_id=g["game_api_id"],
                title=g["title"],
                image_url=g["image_url"],
                owner_username=current_user.username,
                platform="Outro",
                status="Jogando",
                category="RPG",
            )
            db.add(new_game)
            imported_count += 1

    db.commit()
    return {
        "status": "success",
        "message": f"RetroAchievements sincronizado! {imported_count} jogo(s) importado(s).",
        "ra_username": payload.ra_username,
        "ra_points": 8420,
        "ra_ratio": "2.4",
        "ra_rank": 3120,
    }


@app.post("/api/profile/disconnect-retroachievements")
async def disconnect_retroachievements(
    db: Session = Depends(get_db),
    current_user: UserTable = Depends(get_current_active_user),
):
    current_user.ra_username = None
    db.commit()
    return {"status": "success", "message": "RetroAchievements desconectado."}
