from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import jwt as pyjwt
from datetime import datetime, timedelta
from typing import Optional

app = FastAPI()

#cекретный ключ для подписи JWT
SECRET_KEY = "your_secret_key_here"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def authenticate_user(username: str, password: str) -> bool:
    try:
        return username == "john_doe" and password == "securepassword123"
    except Exception as e:
        print(f"Ошибка аутентификации: {e}")
        return False

class LoginRequest(BaseModel):
    username: str
    password: str

security = HTTPBearer()

def generate_token(data: dict):
    try:
        to_encode = data.copy()
        if "exp" not in to_encode:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            to_encode.update({"exp": expire})
        encoded_jwt = pyjwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    except Exception as e:
        print(f"Ошибка генерации токена: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

def verify_token(token: str):
    try:
        payload = pyjwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        print(f"Ошибка проверки токена: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/login")
async def login(request: LoginRequest):
    try:
        if authenticate_user(request.username, request.password):
            access_token = generate_token({"sub": request.username})
            return {"access_token": access_token}
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials")
    except Exception as e:
        print(f"Ошибка обработки запроса: {e}")
        return JSONResponse(status_code=500, content={"detail": "Internal Server Error"})

@app.get("/protected_resource")
async def protected_resource(token: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = verify_token(token.credentials)
        return {"message": f"Hello, {payload['sub']}!"}
    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"Ошибка доступа к защищенному ресурсу: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
