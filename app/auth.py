from pydantic import BaseModel, EmailStr, validator
from datetime import datetime, date
from typing import Optional

class UserCreate(BaseModel):
    nom: str
    prenom: str
    email: EmailStr
    telephone: Optional[str] = None
    password: str
    adresse: Optional[str] = None
    ville: Optional[str] = None
    pays: str = "RDC"
    profession: Optional[str] = None
    date_naissance: Optional[date] = None
    accept_terms: bool
    
    @validator('password')
    def password_strength(cls, v):
        if len(v) < 6:
            raise ValueError('Le mot de passe doit contenir au moins 6 caractères')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    nom: str
    prenom: str
    email: str
    telephone: Optional[str]
    ville: Optional[str]
    pays: str
    profession: Optional[str]
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse