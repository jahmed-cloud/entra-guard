from pydantic import BaseModel, Field
from typing import Optional

class LoginRequest(BaseModel):
    # Upper bounds stop a multi-megabyte "password" from being fed to PBKDF2.
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=1024)

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

class MSALCallbackRequest(BaseModel):
    code: str
    state: Optional[str] = None
    session_state: Optional[str] = None
