from pydantic import BaseModel
from typing import Optional

class LoginRequest(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

class MSALCallbackRequest(BaseModel):
    code: str
    state: Optional[str] = None
    session_state: Optional[str] = None
