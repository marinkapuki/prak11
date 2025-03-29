from datetime import datetime, timedelta, timezone
from typing import Annotated
import jwt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer
from pydantic import BaseModel
import random

app = FastAPI()
security = HTTPBearer()

# Конфигурация JWT
SECRET_KEY = "your-secret-key"  # Сгенерируйте через: openssl rand -hex 32
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Заглушка для имитации проверки пользователя
def authenticate_user(username: str, password: str) -> bool:
    return random.choice([True, False])  # Замените на реальную проверку

# Модель для запроса на аутентификацию
class LoginRequest(BaseModel):
    username: str
    password: str

# Генерация JWT-токена
def create_jwt_token(data: dict) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# Проверка токена
async def get_current_user(token: Annotated[str, Depends(security)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise credentials_exception
