import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "ml")))

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from app import models, schemas, auth
from app.database import engine, get_db
from app.rbac import require_role, get_current_user
from risk_api import router as risk_router
from predict_api import router as predict_router
from investigation_api import router as investigation_router
from ueba_api import router as ueba_router

models.Base.metadata.create_all(bind=engine)
app = FastAPI(title="Insider Threat Behavioral Intelligence System")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(risk_router)
app.include_router(predict_router)
app.include_router(investigation_router)
app.include_router(ueba_router)

@app.post("/register", response_model=schemas.UserOut)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(models.User).filter(
        (models.User.username == user.username) | (models.User.email == user.email)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already registered")
    new_user = models.User(
        username=user.username,
        email=user.email,
        hashed_password=auth.hash_password(user.password),
        role=user.role,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = auth.create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/")
def root():
    return {"status": "Insider Threat backend is running"}

@app.post("/employees", response_model=schemas.EmployeeOut)
def create_employee(
    employee: schemas.EmployeeCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin", "security_manager")),
):
    existing = db.query(models.Employee).filter(models.Employee.employee_id == employee.employee_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Employee ID already exists")
    new_emp = models.Employee(**employee.dict())
    db.add(new_emp)
    db.commit()
    db.refresh(new_emp)
    return new_emp

@app.get("/employees", response_model=list[schemas.EmployeeOut])
def list_employees(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    return db.query(models.Employee).all()

@app.get("/employees/{employee_id}", response_model=schemas.EmployeeOut)
def get_employee(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    emp = db.query(models.Employee).filter(models.Employee.employee_id == employee_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    return emp

@app.delete("/employees/{employee_id}")
def delete_employee(
    employee_id: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(require_role("admin")),
):
    emp = db.query(models.Employee).filter(models.Employee.employee_id == employee_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    db.delete(emp)
    db.commit()
    return {"detail": f"Employee {employee_id} deleted"}