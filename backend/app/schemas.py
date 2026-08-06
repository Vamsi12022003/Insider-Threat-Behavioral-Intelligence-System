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

class EmployeeCreate(BaseModel):
    employee_id: str
    full_name: str
    department: str | None = None
    designation: str | None = None
    manager: str | None = None
    device_info: str | None = None
    access_privileges: str | None = None

class EmployeeOut(BaseModel):
    id: int
    employee_id: str
    full_name: str
    department: str | None
    designation: str | None
    manager: str | None
    device_info: str | None
    access_privileges: str | None
    class Config:
        from_attributes = True
