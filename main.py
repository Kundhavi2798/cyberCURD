from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import uuid
from datetime import datetime
from passlib.context import CryptContext
import jwt

DATABASE_URL = "mysql+pymysql://admin:kundhavi@localhost/notes_app"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

app = FastAPI()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your_secret_key"

class User(Base):
    __tablename__ = "users"
    user_id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_name = Column(String(255), unique=True, nullable=False)
    user_email = Column(String(255), unique=True, nullable=False)
    password = Column(String(255), nullable=False)
    created_on = Column(DateTime, default=datetime.utcnow)
    last_update = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/register")
def register(user_name: str, user_email: str, password: str, db: Session = Depends(get_db)):
    hashed_password = pwd_context.hash(password)
    new_user = User(user_name=user_name, user_email=user_email, password=hashed_password)
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/login")
def login(user_email: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_email == user_email).first()
    if not user or not pwd_context.verify(password, user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = jwt.encode({"user_id": user.user_id}, SECRET_KEY, algorithm="HS256")
    return {"token": token, "user": {"user_id": user.user_id, "user_name": user.user_name, "user_email": user.user_email}}
