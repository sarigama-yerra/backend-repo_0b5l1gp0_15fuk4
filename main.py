import os
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from passlib.context import CryptContext

from database import db, create_document, get_documents

# Environment / Security
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-change-me")
JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "60"))

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------- Models ----------------------
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]

class RequestReset(BaseModel):
    email: EmailStr

class PerformReset(BaseModel):
    token: str
    new_password: str

# ---------------------- Utils ----------------------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=JWT_EXPIRES_MIN))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)
    return encoded_jwt


def get_user_by_email(email: str) -> Optional[dict]:
    users = get_documents("user", {"email": email})
    return users[0] if users else None


def public_user(user_doc: dict) -> dict:
    if not user_doc:
        return {}
    return {
        "id": str(user_doc.get("_id")),
        "name": user_doc.get("name"),
        "email": user_doc.get("email"),
        "role": user_doc.get("role", "user"),
        "avatar_url": user_doc.get("avatar_url"),
        "is_active": user_doc.get("is_active", True),
    }

async def get_current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        user = get_user_by_email(email)
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
        if not user.get("is_active", True):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive")
        return user
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def require_role(required: str):
    def dep(user: dict = Depends(get_current_user)):
        role_order = {"user": 1, "manager": 2, "admin": 3}
        have = user.get("role", "user")
        if role_order.get(have, 0) < role_order.get(required, 0):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return dep

# ---------------------- Routes ----------------------
@app.get("/")
def read_root():
    return {"message": "SaaS Backend Running"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set",
        "database_name": "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set",
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            try:
                response["collections"] = db.list_collection_names()[:10]
                response["connection_status"] = "Connected"
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️ Connected but Error: {str(e)[:80]}"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response

@app.get("/schema")
def schema_info():
    # Minimal schema info for viewer
    return {
        "collections": [
            {"name": "user", "fields": ["name", "email", "password_hash", "role", "avatar_url", "is_active", "reset_token"]},
            {"name": "metric", "fields": ["key", "value", "label"]},
            {"name": "notification", "fields": ["user_id", "title", "message", "type", "is_read"]},
        ]
    }

# Auth
@app.post("/auth/signup", response_model=TokenResponse)
def signup(payload: SignupRequest):
    if get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "name": payload.name,
        "email": str(payload.email).lower(),
        "password_hash": hash_password(payload.password),
        "role": "user",
        "avatar_url": None,
        "is_active": True,
        "reset_token": None,
    }
    create_document("user", user_doc)
    token = create_access_token({"sub": user_doc["email"], "role": user_doc["role"]})
    return {"access_token": token, "user": public_user(user_doc), "token_type": "bearer"}

@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest):
    user = get_user_by_email(str(payload.email).lower())
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": user.get("email"), "role": user.get("role", "user")})
    return {"access_token": token, "user": public_user(user), "token_type": "bearer"}

@app.post("/auth/request-password-reset")
def request_password_reset(payload: RequestReset):
    user = get_user_by_email(str(payload.email).lower())
    if not user:
        return {"ok": True}  # avoid user enumeration
    # Create a short-lived reset token
    reset_token = create_access_token({"sub": user.get("email"), "type": "reset"}, expires_delta=timedelta(minutes=15))
    # Store token hash or token itself (for demo, store token)
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"reset_token": reset_token, "updated_at": datetime.now(timezone.utc)}})
    # In real app, email the link with token
    return {"ok": True, "reset_token": reset_token}

@app.post("/auth/reset-password")
def reset_password(payload: PerformReset):
    # Validate token
    try:
        data = jwt.decode(payload.token, JWT_SECRET, algorithms=[JWT_ALG])
        if data.get("type") != "reset":
            raise HTTPException(status_code=400, detail="Invalid reset token")
        email = data.get("sub")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    user = get_user_by_email(email)
    if not user or user.get("reset_token") != payload.token:
        raise HTTPException(status_code=400, detail="Invalid token")
    new_hash = hash_password(payload.new_password)
    db["user"].update_one({"_id": user["_id"]}, {"$set": {"password_hash": new_hash, "reset_token": None, "updated_at": datetime.now(timezone.utc)}})
    return {"ok": True}

@app.get("/me")
def me(user: dict = Depends(get_current_user)):
    return public_user(user)

# Dashboard data
@app.get("/metrics")
def metrics(user: dict = Depends(get_current_user)):
    # Return some example metrics and series for charts
    series = [
        {"label": "Revenue", "data": [12, 19, 14, 25, 32, 28, 40]},
        {"label": "Users", "data": [5, 9, 7, 12, 15, 18, 22]},
    ]
    kpis = [
        {"title": "MRR", "value": "$42,300", "delta": "+6.2%"},
        {"title": "Active Users", "value": "2,318", "delta": "+3.1%"},
        {"title": "Churn", "value": "2.4%", "delta": "-0.3%"},
    ]
    table = [
        {"name": "Acme Inc", "plan": "Enterprise", "seats": 120, "mrr": 5400},
        {"name": "Nova Labs", "plan": "Pro", "seats": 24, "mrr": 960},
        {"name": "Pixel Co", "plan": "Starter", "seats": 6, "mrr": 120},
    ]
    return {"series": series, "kpis": kpis, "table": table}

@app.get("/notifications")
def notifications(user: dict = Depends(get_current_user)):
    # Simple example notifications
    return [
        {"id": "1", "title": "Welcome aboard", "message": "Your account is ready.", "type": "success"},
        {"id": "2", "title": "New feature", "message": "Interactive charts are live!", "type": "info"},
    ]

# Admin-only endpoint
@app.get("/admin/users")
def list_users(_: dict = Depends(require_role("admin"))):
    docs = get_documents("user", {})
    return [public_user(u) for u in docs]

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
