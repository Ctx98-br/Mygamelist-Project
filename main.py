from sqlalchemy.orm import Session
from database import UserTable, get_db

# Altere a assinatura da função get_user
def get_user(db: Session, username: str):
    return db.query(UserTable).filter(UserTable.username == username).first()