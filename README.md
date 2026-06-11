# 🎮 MyGameList — Sua Biblioteca Pessoal & Fórum Gamer

O **MyGameList** é um sistema completo e moderno de catalogação de jogos, acompanhamento de progresso e comunidade integrado em uma interface web rica, responsiva e dinâmica. O sistema permite aos usuários gerenciar sua biblioteca de jogos por plataforma, importar dados de estatísticas das principais redes (Steam, Xbox Live e PlayStation Network) e engajar-se em fóruns temáticos organizados por categorias.

---

## ✨ Funcionalidades Principais

### 1. 🗂️ Gerenciamento da Biblioteca de Jogos
- **Catálogo Geral (RAWG API)**: Busca em tempo real de mais de 500.000 jogos utilizando a base de dados da RAWG.
- **Lista Pessoal**: Adicione jogos à sua biblioteca e acompanhe o progresso de forma estruturada:
  - **Status do Jogo**: *Pretendo Jogar*, *Jogando*, *Completo (100%)*, *Jogado (Parcial)* ou *Pausado/Desistido*.
  - **Avaliação Pessoal**: Dê notas de 0 a 5 estrelas.
  - **Tags Personalizadas**: Crie marcadores personalizados para organizar seus jogos.
  - **Categorias e Plataformas**: Classifique por gênero e console correspondente.
  - **Notas Pessoais**: Registre suas impressões sobre o jogo.

### 2. 🔌 Sincronização & APIs de Consoles
- **Steam Integration**: Importa estatísticas do usuário (horas jogadas, conquistas) se a `STEAM_API_KEY` estiver configurada.
- **Xbox Live Integration (via OpenXBL)**: Conecta o seu Gamertag oficial para ler gamerscore e conquistas. Caso esteja offline, estatísticas determinísticas realistas são simuladas.
- **PlayStation Network (PSN)**: Sincroniza perfis da PSN e gera estatísticas de jogos com base na atividade simulada do ID inserido.
- *Em ambos os casos, a sincronização de consoles importa automaticamente os jogos daquela plataforma para a biblioteca do usuário.*

### 3. 💬 Fórum Estruturado com Categorias
- **Categorização**: Tópicos rotulados com badges de tópicos como *Geral*, *Dúvidas*, *Novidades*, *Reviews* e *Dicas*.
- **Filtros Dinâmicos**: Navegue rapidamente utilizando filtros interativos em formato de pílulas (pills) para focar no assunto de interesse.
- **Modo Anônimo**: Opção de publicar tópicos e comentários anonimamente (`anon`), ocultando o autor.
- **Interação**: Sistema de Likes para posts e comentários.

### 4. 🛡️ Painel Admin & Moderação
- **Gestão de Usuários**: Visualização de todos os cadastrados com poder de exclusão de contas.
- **Auto-Promoção**: Elevação de privilégios usando um código mestre secreto.
- **Escudos Administrativos**: Substituição de coroas por escudos de moderação para sinalizar o status de administrador.
- **Moderação Completa no Fórum**:
  - Exclusão de qualquer tópico/post diretamente do feed (e exclusão em cascata de comentários).
  - Exclusão de comentários individuais no feed.
  - Painel de moderação centralizado em tabela alinhada.

---

## 🛠️ Tecnologias Utilizadas

- **Backend**: FastAPI (Python 3.12)
- **Banco de Dados**: PostgreSQL 16 (produção/Docker) / SQLite (ambiente de testes locais)
- **ORM**: SQLAlchemy
- **Autenticação**: OAuth2, JWT Tokens, Cookies de Sessão e Integração Google OAuth (Authlib)
- **Frontend**: HTML5 Semântico, CSS3 (design premium com suporte a temas e micro-animações) e JavaScript puro (Vanilla JS)
- **Containerização**: Docker e Docker Compose

---

## 📦 Como Executar o Projeto com Docker (Recomendado)

O Docker criará automaticamente um banco de dados PostgreSQL e configurará o contêiner do FastAPI sem necessidade de instalação local de dependências do Python.

### Pré-requisitos
- Docker instalado ([Instruções](https://docs.docker.com/get-docker/))
- Docker Compose instalado

### Passos para Inicialização

1. **Clonar o Repositório**:
   ```bash
   git clone https://github.com/Ctx98-br/Mygamelist-Project.git
   cd Mygamelist-Project
   ```

2. **Configurar Variáveis de Ambiente**:
   Copie o arquivo `.env.example` para `.env` e ajuste as configurações desejadas (veja a seção de configuração abaixo):
   ```bash
   cp .env.example .env
   ```

3. **Subir os Contêineres**:
   Execute o seguinte comando para construir a imagem e iniciar os serviços:
   ```bash
   docker compose up --build
   ```

4. **Acessar a Aplicação**:
   Abra seu navegador e navegue para:
   - **Interface Web**: `http://localhost:8000`
   - **Documentação de API (Swagger)**: `http://localhost:8000/docs`

---

## 🔧 Configuração (.env)

O arquivo `.env` controla chaves de API essenciais para o funcionamento de integrações externas:

```ini
# --- SEGURANÇA ---
SESSION_SECRET=troque-por-uma-string-secreta-longa  # Chave para criptografia JWT

# --- RECUPERAÇÃO DE SENHA (SMTP) ---
SMTP_EMAIL=seuemail@gmail.com
SMTP_PASSWORD=xxxx-xxxx-xxxx-xxxx  # Senha de Aplicativo gerada no Google Account

# --- GOOGLE OAUTH (Login com Google) ---
GOOGLE_CLIENT_ID=seu-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=seu-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8000/auth/google/callback

# --- APIS DE JOGOS & CONSOLES ---
RAWG_API_KEY=sua-chave-rawg          # Busca do catálogo (https://rawg.io/apidocs)
STEAM_API_KEY=sua-chave-steam        # Sincronização Steam (https://steamcommunity.com/dev/apikey)
OPENXBL_API_KEY=sua-chave-openxbl    # Sincronização Xbox (https://xbl.io/)
```

---

## 🔑 Configuração da Autenticação do Google (Google OAuth2)

Para habilitar o login rápido utilizando uma Conta do Google:

1. Acesse o [Google Cloud Console](https://console.cloud.google.com/).
2. Crie um novo projeto ou selecione um existente.
3. Vá em **APIs & Serviços** > **Tela de consentimento OAuth**, selecione o tipo de usuário e preencha as informações do app.
4. Vá em **Credenciais** > **Criar credenciais** > **ID do cliente OAuth**.
5. Selecione **Aplicativo da Web** e preencha:
   - **Origens JavaScript autorizadas**: `http://localhost:8000`
   - **URIs de redirecionamento autorizados**: `http://localhost:8000/auth/google/callback`
6. Clique em criar e copie o **Client ID** e **Client Secret** obtidos para o seu arquivo `.env`.

---

## 🛡️ Ativação do Primeiro Administrador (Master Code)

Para promover o primeiro usuário do sistema à função de administrador para moderar o fórum e gerenciar contas:

1. Crie uma conta normalmente pelo formulário de registro da aplicação.
2. Estando logado, clique no botão de configuração/perfil ou acesse a rota secreta de promoção no console do navegador fazendo um POST HTTP. O código de administrador configurado internamente é:
   ```txt
   mgl-admin-2025
   ```
3. Alternativamente, você pode executar o seguinte comando no console JS do seu navegador enquanto estiver logado na aplicação:
   ```javascript
   fetch('/api/admin/promote-self', {
     method: 'POST',
     headers: {
       'Content-Type': 'application/json',
       'Authorization': 'Bearer ' + localStorage.getItem('access_token')
     },
     body: JSON.stringify({ codigo: "mgl-admin-2025" })
   })
   .then(res => res.json())
   .then(data => alert("Promovido com sucesso! Reinicie a sessão para ver as ferramentas de moderador."));
   ```

---

## 🧪 Como Executar a Suíte de Testes (Local)

Caso queira realizar testes unitários localmente na máquina host:

1. Crie o ambiente virtual e instale as dependências:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r reqs.txt
   ```
2. Execute o script de testes:
   ```bash
   python3 .gemini/antigravity/brain/a8c491bf-2e42-4f29-98f2-67faac654069/scratch/test_endpoints.py
   ```
