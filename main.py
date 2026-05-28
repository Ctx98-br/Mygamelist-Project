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
            "category": g.category,
            "status": g.status,
            "platform": g.platform,
        }
        for g in games
    ]
