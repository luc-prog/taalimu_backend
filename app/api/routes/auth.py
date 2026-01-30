# app/api/routes/auth.py
from fastapi import APIRouter, Depends, HTTPException, status, Form
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import secrets

from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import RegisterIn, UserOut, TokenOut
from app.core.security import get_password_hash, verify_password, create_access_token
from app.services.email_service import send_email
from app.core.config import settings

router = APIRouter(prefix="/api/auth", tags=["auth"])

@router.post("/register", response_model=UserOut)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == payload.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(payload.password)
    user = User(email=payload.email, full_name=payload.full_name, hashed_password=hashed, phone=payload.phone, role=payload.role)
    db.add(user); db.commit(); db.refresh(user)

    # generate confirmation code
    code = f"{secrets.randbelow(999999):06d}"
    expires = datetime.utcnow() + timedelta(minutes=30)
    user.confirmation_code = code
    user.confirmation_expires = expires
    db.add(user); db.commit(); db.refresh(user)

    confirm_link = f"{settings.FRONTEND_URL}/confirm-email?email={user.email}"
    html = f"""
        <p>Bonjour {user.full_name or ''},</p>
        <p>Votre code de confirmation Taalimu : <strong>{code}</strong></p>
        <p>Ce code expire dans 30 minutes.</p>
        <p>Ou cliquez ici : <a href="{confirm_link}">Confirmer mon email</a></p>
    """
    try:
        send_email("Confirmez votre email Taalimu", user.email, html)
    except Exception as e:
        # log mais on continue: l'utilisateur est créé
        print("Email send error:", e)

    return user

@router.post("/confirm")
def confirm_email(email: str = Form(...), code: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_confirmed:
        return {"ok": True, "msg": "Already confirmed"}
    if not user.confirmation_code or user.confirmation_code != code or (user.confirmation_expires and user.confirmation_expires < datetime.utcnow()):
        raise HTTPException(status_code=400, detail="Invalid or expired code")
    user.is_confirmed = True
    user.confirmation_code = None
    user.confirmation_expires = None
    db.add(user); db.commit(); db.refresh(user)
    return {"ok": True}

@router.post("/login", response_model=TokenOut)
def login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    if not user.is_confirmed:
        raise HTTPException(status_code=403, detail="Email not confirmed")
    token = create_access_token(subject=user.email)
    return {"access_token": token, "token_type": "bearer"}

@router.post("/forgot-password")
def forgot_password(email: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"ok": True}
    token = secrets.token_urlsafe(32)
    expires = datetime.utcnow() + timedelta(minutes=30)
    user.reset_token = token
    user.reset_expires = expires
    db.add(user); db.commit(); db.refresh(user)

    reset_link = f"{settings.FRONTEND_URL}/reset-password?token={token}&email={user.email}"
    html = f"""
        <p>Bonjour,</p>
        <p>Vous avez demandé la réinitialisation de mot de passe. Cliquez ici : <a href="{reset_link}">Réinitialiser</a></p>
        <p>Ou utilisez ce code : <strong>{token}</strong></p>
    """
    try:
        send_email("Réinitialisation mot de passe - Taalimu", user.email, html)
    except Exception as e:
        print("Email send error:", e)
    return {"ok": True}

@router.post("/reset-password")
def reset_password(email: str = Form(...), token: str = Form(...), new_password: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not user.reset_token or user.reset_token != token or (user.reset_expires and user.reset_expires < datetime.utcnow()):
        raise HTTPException(status_code=400, detail="Invalid token or expired")
    user.hashed_password = get_password_hash(new_password)
    user.reset_token = None
    user.reset_expires = None
    db.add(user); db.commit(); db.refresh(user)
    return {"ok": True}
