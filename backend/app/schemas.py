from pydantic import BaseModel, EmailStr
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "security_analyst"
class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    class Config:
        from_attributes = True
class Token(BaseModel):
    access_token: str
    token_type: str
class LoginRequest(BaseModel):
    username: str
    password: str
