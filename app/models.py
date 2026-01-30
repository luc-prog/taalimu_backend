from sqlalchemy import Column, Integer, String, Boolean, Text, Date, DateTime
from sqlalchemy.sql import func
from app.database import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    nom = Column(String(100), nullable=False)
    prenom = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    telephone = Column(String(20), nullable=True)
    password_hash = Column(String(255), nullable=False)
    adresse = Column(Text, nullable=True)
    ville = Column(String(100), nullable=True)
    pays = Column(String(100), default="RDC")
    profession = Column(String(100), nullable=True)
    date_naissance = Column(Date, nullable=True)
    accept_terms = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    role = Column(String(50), default="user")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())