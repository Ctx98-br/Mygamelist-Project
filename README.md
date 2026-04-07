# Mygamelist-Project
Um projeto de lista de jogos para o projeto web

Crie um ambiente virtual com o comando:

python3 -m venv .venv

*Certifique-se que o pacote python3-venv esteja instalado, senão instale no seu sistema operacional

Depois de criar o ambiente virtual, ative ele toda vez que for iniciar uma nova sessão no termina com o comando:

source .venv/bin/activate

vai ficar ativado o (.venv), assim: 
(.venv) user@user

Verifique se o comando funcionou corretamente, fazendo este comando, mas é opicional, se apareceu o (.venv) é porque deu certo:

which python

Deve aparecer: /home/user/Mygamelist-Project-main/.venv/bin/python

Daí é só baixar os requerimentos com este comando:

pip install -r Reqs.txt

Para executar o projeto: 

fastapi dev login.py
