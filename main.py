import json  # Pour parser les données JSON
from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from datetime import datetime, timedelta
from typing import Optional, List
import sqlite3
from fastapi.responses import FileResponse
import os
from passlib.context import CryptContext
from jose import jwt
import re
import logging

from fastapi.security import OAuth2PasswordBearer
import shutil

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Configuration OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
SECRET_KEY = "taalimu-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

app = FastAPI(title="Taalimu Auth API")

# CORS - autorise tout pour tester
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration SQLite (fichier local)
DB_FILE = "taalimu.db"

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ============ FONCTIONS UTILITAIRES ============

def get_db():
    """Connexion à la base SQLite"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # Pour avoir des dictionnaires
    return conn

def init_db():
    """Initialise la base de données SQLite avec toutes les tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Table users améliorée
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nom TEXT NOT NULL,
        prenom TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        telephone TEXT,
        password_hash TEXT NOT NULL,
        adresse TEXT DEFAULT '',
        ville TEXT DEFAULT '',
        pays TEXT DEFAULT 'RDC',
        profession TEXT DEFAULT '',
        date_naissance TEXT,
        accept_terms BOOLEAN DEFAULT FALSE,
        is_active BOOLEAN DEFAULT TRUE,
        role TEXT DEFAULT 'user',
        diplome TEXT DEFAULT '',
        experience TEXT DEFAULT '',
        etablissement TEXT DEFAULT '',
        matieres TEXT DEFAULT '[]',
        tarif_horaire INTEGER DEFAULT 0,
        description TEXT DEFAULT '',
        disponibilites TEXT DEFAULT '[]',
        is_verified BOOLEAN DEFAULT FALSE,
        verification_status TEXT DEFAULT 'pending',
        verification_notes TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    
    # Table pour les documents uploadés
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        document_type TEXT NOT NULL,
        file_path TEXT NOT NULL,
        file_name TEXT NOT NULL,
        file_size INTEGER,
        file_type TEXT,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    
    # Table pour les enfants des parents
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS enfants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_id INTEGER NOT NULL,
        nom TEXT NOT NULL,
        prenom TEXT NOT NULL,
        age INTEGER,
        classe TEXT,
        niveau TEXT,
        ecole TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (parent_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    

    # Table pour les devoirs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devoirs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_id INTEGER NOT NULL,
        enfant_id INTEGER NOT NULL,
        titre TEXT NOT NULL,
        description TEXT,
        matiere TEXT NOT NULL,
        date_remise DATE NOT NULL,
        niveau TEXT,
        type_devoir TEXT DEFAULT 'ecrit',
        priorite TEXT DEFAULT 'normal',
        date_envoi TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        statut TEXT DEFAULT 'envoyé',
        notes_tuteur TEXT,
        note INTEGER,
        date_correction TIMESTAMP,
        tuteur_id INTEGER,
        FOREIGN KEY (parent_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (enfant_id) REFERENCES enfants(id) ON DELETE CASCADE,
        FOREIGN KEY (tuteur_id) REFERENCES users(id) ON DELETE SET NULL
    )
    """)


# Duplicate enfants table removed (already created above)
    
    # Table pour les fichiers des devoirs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devoir_fichiers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        devoir_id INTEGER NOT NULL,
        nom_fichier TEXT NOT NULL,
        chemin_fichier TEXT NOT NULL,
        type_fichier TEXT,
        taille INTEGER,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (devoir_id) REFERENCES devoirs(id) ON DELETE CASCADE
    )
    """)
    
   # Table pour les travaux corrigés (AJOUTÉE ICI - notez l'indentation)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS travaux_corriges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tuteur_id INTEGER NOT NULL,
        titre TEXT NOT NULL,
        description TEXT,
        matiere TEXT NOT NULL,
        niveau TEXT NOT NULL,
        type_travail TEXT DEFAULT 'devoir',
        date_travail DATE,
        date_correction DATE NOT NULL,
        note_maximale DECIMAL(5,2) DEFAULT 20,
        difficulte TEXT DEFAULT 'moyen',
        temps_estime TEXT,
        competences TEXT,
        points_forts TEXT,
        points_amelioration TEXT,
        commentaires_generaux TEXT,
        statut TEXT DEFAULT 'publié',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (tuteur_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)
    
    # Table pour les fichiers des travaux corrigés
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS travail_corrige_fichiers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        travail_id INTEGER NOT NULL,
        nom_fichier TEXT NOT NULL,
        chemin_fichier TEXT NOT NULL,
        type_fichier TEXT,
        taille INTEGER,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (travail_id) REFERENCES travaux_corriges(id) ON DELETE CASCADE
    )
    """)
    
    # Table pour les fichiers de corrections
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS correction_fichiers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        correction_id INTEGER NOT NULL,
        nom_fichier TEXT NOT NULL,
        chemin_fichier TEXT NOT NULL,
        type_fichier TEXT,
        taille INTEGER,
        categorie TEXT DEFAULT 'correction',
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (correction_id) REFERENCES corrections(id) ON DELETE CASCADE
    )
    """)
    
    # Table pour l'assignation des devoirs aux tuteurs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devoir_assignations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        devoir_id INTEGER NOT NULL,
        tuteur_id INTEGER NOT NULL,
        assigne_par INTEGER,
        date_assignation TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        date_limite DATE,
        priorite TEXT DEFAULT 'normal',
        statut TEXT DEFAULT 'assigné',
        notes TEXT,
        FOREIGN KEY (devoir_id) REFERENCES devoirs(id) ON DELETE CASCADE,
        FOREIGN KEY (tuteur_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (assigne_par) REFERENCES users(id) ON DELETE SET NULL
    )
    """)
    
    conn.commit()
    conn.close()
    logger.info("✅ Base SQLite initialisée avec toutes les tables")

def hash_password(password: str) -> str:
    """Hash simple et robuste"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérification simple"""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    """Crée un token JWT"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Récupère l'utilisateur connecté"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, nom, prenom, email, telephone, role, 
                   is_active, created_at
            FROM users WHERE id = ?
        """, (user_id,))
        
        row = cursor.fetchone()
        if not row:
            raise HTTPException(404, "Utilisateur non trouvé")
        
        conn.close()
        
        return dict(row)  # ← Ceci doit contenir {"id": ..., ...}
        
    except jwt.JWTError:
        raise HTTPException(401, "Token invalide")
    except Exception as e:
        logger.error(f"❌ Erreur récupération utilisateur: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")
async def save_uploaded_file(file: UploadFile, user_id: int, doc_type: str) -> str:
    """Sauvegarde un fichier uploadé"""
    try:
        # Créer le dossier uploads s'il n'existe pas
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        
        # Générer un nom de fichier sécurisé
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_ext = os.path.splitext(file.filename)[1]
        safe_filename = f"{user_id}_{doc_type}_{timestamp}{file_ext}"
        file_path = os.path.join(UPLOAD_DIR, safe_filename)
        
        # Sauvegarder le fichier
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        logger.info(f"📁 Fichier sauvegardé: {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"❌ Erreur sauvegarde fichier: {str(e)}")
        raise HTTPException(500, f"Erreur sauvegarde fichier: {str(e)}")

# ============ MODÈLES PYDANTIC ============

class UserCreate(BaseModel):
    nom: str
    prenom: str
    email: str
    telephone: str = ""
    password: str
    adresse: str = ""
    ville: str = ""
    pays: str = "RDC"
    profession: str = ""
    date_naissance: Optional[str] = None
    accept_terms: bool
    
    @validator('email')
    def validate_email(cls, v):
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, v):
            raise ValueError('Email invalide')
        return v
    
    @validator('password')
    def password_strength(cls, v):
        if len(v) < 4:
            raise ValueError('Le mot de passe doit contenir au moins 4 caractères')
        return v

class UserLogin(BaseModel):
    email: str
    password: str
    
    @validator('email')
    def validate_email(cls, v):
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, v):
            raise ValueError('Email invalide')
        return v

class UserResponse(BaseModel):
    id: int
    nom: str
    prenom: str
    email: str
    telephone: str = ""
    is_active: bool
    created_at: datetime
    role: Optional[str] = "user"
    
    class Config:
        extra = "ignore"

# À la ligne ~1110 - Modifiez la classe CorrectionCreate
class CorrectionCreate(BaseModel):
    devoir_id: int
    tuteur_id: int
    note: float
    commentaires: str
    remarques: str = ""
    recommandations: str = ""
    temps_passe: Optional[float] = None
    difficulte: str = "moyenne"
    status_correction: str = "corrigé"
    date_correction: str
    
    # Nouveaux champs
    type_correction: str = "correction_detaille"
    format_explication: str = "textuel"
    niveau_detail: str = "intermediaire"
    methode_resolution: str = "standard"
    points_cles: str = ""
    erreurs_communes: str = ""
    conseils_pratiques: str = ""
    ressources_complementaires: str = ""
    temps_estime_eleve: Optional[str] = None

class EnfantCreate(BaseModel):
    nom: str
    prenom: str
    age: int = 0
    classe: str = ""
    niveau: str = ""
    ecole: str = ""

class TravailCorrigeCreate(BaseModel):
    tuteur_id: int
    titre: str
    description: str = ""
    matiere: str
    niveau: str
    type_travail: str = "devoir"
    date_travail: str = ""
    date_correction: str
    note_maximale: float = 20
    difficulte: str = "moyen"
    temps_estime: str = ""
    competences: str = ""
    points_forts: str = ""
    points_amelioration: str = ""
    commentaires_generaux: str = ""
    statut: str = "publié"

class TravailCorrigeResponse(BaseModel):
    id: int
    tuteur_id: int
    titre: str
    description: str
    matiere: str
    niveau: str
    type_travail: str
    date_travail: Optional[str]
    date_correction: str
    note_maximale: float
    difficulte: str
    temps_estime: str
    competences: str
    points_forts: str
    points_amelioration: str
    commentaires_generaux: str
    statut: str
    created_at: datetime
    
    class Config:
        from_attributes = True

class CorrectionCreate(BaseModel):
    devoir_id: int
    tuteur_id: int
    note: float
    commentaires: str
    remarques: str = ""
    recommandations: str = ""
    temps_passe: Optional[float] = None
    difficulte: str = "moyenne"
    status_correction: str = "corrigé"
    date_correction: str
    
    # Nouveaux champs
    type_correction: str = "correction_detaille"
    format_explication: str = "textuel"
    niveau_detail: str = "intermediaire"
    methode_resolution: str = "standard"
    points_cles: str = ""
    erreurs_communes: str = ""
    conseils_pratiques: str = ""
    ressources_complementaires: str = ""
    temps_estime_eleve: Optional[str] = None
class DevoirParentCreate(BaseModel):
    parent_id: int
    enfant_id: int
    titre: str
    description: str = ""
    matiere: str
    date_remise: str
    niveau: str = ""
    type_devoir: str = "ecrit"
    priorite: str = "normal"
    statut: str = "envoyé"

class DevoirParentResponse(BaseModel):
    id: int
    parent_id: int
    enfant_id: int
    titre: str
    description: str
    matiere: str
    date_remise: str
    niveau: str
    type_devoir: str
    priorite: str
    date_envoi: datetime
    statut: str
    parent_nom: Optional[str] = None
    parent_prenom: Optional[str] = None
    enfant_nom: Optional[str] = None
    enfant_prenom: Optional[str] = None
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class CorrectionCreate(BaseModel):
    devoir_id: int
    tuteur_id: int
    note: float
    commentaires: str
    remarques: str = ""
    recommandations: str = ""
    temps_passe: Optional[float] = None
    difficulte: str = "moyenne"
    status_correction: str = "corrigé"
    date_correction: str

class CorrectionResponse(BaseModel):
    id: int
    devoir_id: int
    tuteur_id: int
    note: float
    commentaires: str
    remarques: str
    recommandations: str
    temps_passe: Optional[float]
    difficulte: str
    status_correction: str
    date_correction: datetime
    date_envoi: datetime

    class Config:
        from_attributes = True

class DevoirCreate(BaseModel):
    parent_id: int
    enfant_id: int
    titre: str
    description: str = ""
    matiere: str
    date_remise: str
    niveau: str = ""
    type_devoir: str = "ecrit"
    priorite: str = "normal"
    statut: str = "envoyé"

class FichierDevoir(BaseModel):
    devoir_id: int
    nom_fichier: str
    chemin_fichier: str
    type_fichier: str
    taille: int

class DevoirResponse(BaseModel):
    id: int
    parent_id: int
    enfant_id: int
    titre: str
    description: str
    matiere: str
    date_remise: str
    niveau: str
    type_devoir: str
    priorite: str
    date_envoi: datetime
    statut: str
    fichiers: List[FichierDevoir] = []

    class Config:
        from_attributes = True

class DevoirParentCreate(BaseModel):
    parent_id: int
    enfant_id: int
    titre: str
    description: str = ""
    matiere: str
    date_remise: str
    niveau: str = ""
    type_devoir: str = "ecrit"
    priorite: str = "normal"
    statut: str = "envoyé"
    fichiers: Optional[List[dict]] = None  # Ajoutez ce champ
# ============ ÉVÉNEMENTS DE DÉMARRAGE ============

@app.on_event("startup")
async def startup_event():
    logger.info("🚀 Démarrage API Taalimu avec SQLite...")
    init_db()
    logger.info("✅ API prête!")

# ============ ENDPOINTS PUBLIC ============

@app.get("/")
async def root():
    return {
        "message": "Taalimu API avec SQLite", 
        "status": "online", 
        "version": "1.0.0",
        "docs": "/docs"
    }


@app.get("/uploads/{path:path}")
async def serve_file(
    path: str,
    current_user = Depends(get_current_user)
):
    """Servir un fichier avec vérification de sécurité"""
    try:
        # Construire le chemin complet
        full_path = os.path.join(UPLOAD_DIR, path)
        
        # Vérifier que le chemin est sécurisé
        if not os.path.exists(full_path):
            raise HTTPException(404, "Fichier non trouvé")
        
        # Vérifier les permissions
        # Vous devriez vérifier si l'utilisateur a accès à ce fichier
        # Cette logique dépend de votre structure
        
        # Servir le fichier
        return FileResponse(
            full_path,
            media_type="application/octet-stream",
            filename=os.path.basename(full_path)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur service fichier: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

# OU - Une version plus sécurisée qui vérifie l'appartenance
@app.get("/devoirs/{devoir_id}/fichiers/{fichier_id}/telecharger")
async def telecharger_fichier_devoir(
    devoir_id: int,
    fichier_id: int,
    current_user = Depends(get_current_user)
):
    """Télécharger un fichier avec vérification des permissions"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que le fichier existe et les permissions
        cursor.execute("""
            SELECT df.*, d.parent_id, d.tuteur_id 
            FROM devoir_fichiers df
            JOIN devoirs d ON df.devoir_id = d.id
            WHERE df.id = ? AND d.id = ?
        """, (fichier_id, devoir_id))
        
        result = cursor.fetchone()
        if not result:
            raise HTTPException(404, "Fichier non trouvé")
        
        fichier = dict(result)
        
        # Vérifier les permissions
        # Parent peut télécharger ses propres fichiers
        # Tuteur peut télécharger les fichiers des devoirs qui lui sont assignés
        # Admin peut tout télécharger
        user_role = current_user.get("role")
        user_id = current_user.get("id")
        
        has_access = False
        if user_role == "admin":
            has_access = True
        elif user_role == "parent" and fichier["parent_id"] == user_id:
            has_access = True
        elif user_role in ["tuteur", "professeur"] and fichier["tuteur_id"] == user_id:
            has_access = True
        elif user_role in ["tuteur", "professeur"]:
            # Vérifier si le tuteur est assigné à ce devoir
            cursor.execute("""
                SELECT id FROM devoir_assignations 
                WHERE devoir_id = ? AND tuteur_id = ?
            """, (devoir_id, user_id))
            assignation = cursor.fetchone()
            if assignation:
                has_access = True
        
        if not has_access:
            raise HTTPException(403, "Accès non autorisé")
        
        # Vérifier que le fichier existe physiquement
        if not os.path.exists(fichier["chemin_fichier"]):
            raise HTTPException(404, "Fichier physique non trouvé")
        
        conn.close()
        
        # Servir le fichier
        return FileResponse(
            fichier["chemin_fichier"],
            media_type="application/octet-stream",
            filename=fichier["nom_fichier"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur téléchargement fichier: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.post("/travaux-corriges/creer")
async def creer_travail_corrige(
    correction_data: str = Form(...),  # Données JSON en string
    fichiers: List[UploadFile] = File(None),
    current_user = Depends(get_current_user)
):
    """Créer un travail corrigé pour les tuteurs"""
    try:
        # Vérifier que l'utilisateur est tuteur
        if current_user["role"] not in ["tuteur", "admin"]:
            raise HTTPException(403, "Seuls les tuteurs peuvent publier des travaux corrigés")
        
        # Parser les données JSON
        try:
            travail_data = json.loads(correction_data)
        except json.JSONDecodeError:
            raise HTTPException(400, "Données JSON invalides")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Insérer le travail corrigé
        cursor.execute("""
            INSERT INTO travaux_corriges (
                tuteur_id, titre, description, matiere, niveau,
                type_travail, date_travail, date_correction, note_maximale,
                difficulte, temps_estime, competences, points_forts,
                points_amelioration, commentaires_generaux, statut
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            current_user["id"],
            travail_data.get("titre", ""),
            travail_data.get("description", ""),
            travail_data.get("matiere", ""),
            travail_data.get("niveau", ""),
            travail_data.get("type_travail", "devoir"),
            travail_data.get("date_travail"),
            travail_data.get("date_correction"),
            float(travail_data.get("note_maximale", 20)),
            travail_data.get("difficulte", "moyen"),
            travail_data.get("temps_estime", ""),
            travail_data.get("competences", ""),
            travail_data.get("points_forts", ""),
            travail_data.get("points_amelioration", ""),
            travail_data.get("commentaires_generaux", ""),
            travail_data.get("statut", "publié")
        ))
        
        travail_id = cursor.lastrowid
        
        # Sauvegarder les fichiers uploadés
        saved_files = []
        if fichiers:
            for fichier in fichiers:
                if fichier and fichier.filename:
                    try:
                        # Créer le dossier uploads/travaux-corriges s'il n'existe pas
                        upload_subdir = os.path.join(UPLOAD_DIR, "travaux-corriges")
                        os.makedirs(upload_subdir, exist_ok=True)
                        
                        # Générer un nom de fichier sécurisé
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        file_ext = os.path.splitext(fichier.filename)[1]
                        safe_filename = f"travail_{travail_id}_{timestamp}_{fichier.filename}"
                        file_path = os.path.join(upload_subdir, safe_filename)
                        
                        # Sauvegarder le fichier
                        with open(file_path, "wb") as buffer:
                            content = await fichier.read()
                            buffer.write(content)
                        
                        # Enregistrer dans la base
                        cursor.execute("""
                            INSERT INTO travail_corrige_fichiers 
                            (travail_id, nom_fichier, chemin_fichier, type_fichier, taille)
                            VALUES (?, ?, ?, ?, ?)
                        """, (
                            travail_id,
                            fichier.filename,
                            file_path,
                            fichier.content_type,
                            len(content)
                        ))
                        
                        saved_files.append({
                            "nom_original": fichier.filename,
                            "chemin": file_path,
                            "type": fichier.content_type,
                            "taille": len(content)
                        })
                        
                    except Exception as e:
                        logger.warning(f"⚠️ Erreur sauvegarde fichier {fichier.filename}: {str(e)}")
                        # Continuer même si un fichier échoue
        
        conn.commit()
        
        # Récupérer le travail créé
        cursor.execute("""
            SELECT tc.*, 
                   u.nom as tuteur_nom, u.prenom as tuteur_prenom,
                   u.role as tuteur_role
            FROM travaux_corriges tc
            JOIN users u ON tc.tuteur_id = u.id
            WHERE tc.id = ?
        """, (travail_id,))
        
        row = cursor.fetchone()
        if row:
            travail = dict(row)
        else:
            travail = None
        
        # Récupérer les fichiers associés
        cursor.execute("""
            SELECT * FROM travail_corrige_fichiers 
            WHERE travail_id = ?
            ORDER BY uploaded_at
        """, (travail_id,))
        
        fichiers_rows = cursor.fetchall()
        travail["fichiers"] = [dict(f) for f in fichiers_rows]
        
        conn.close()
        
        return {
            "success": True,
            "message": "Travail corrigé publié avec succès",
            "travail_id": travail_id,
            "travail": travail,
            "fichiers_sauvegardes": len(saved_files)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur création travail corrigé: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/users/{user_id}/details")
async def get_user_details(user_id: int, current_user = Depends(get_current_user)):
    """Récupère les détails complets d'un utilisateur"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Récupérer l'utilisateur
        cursor.execute("""
            SELECT * FROM users WHERE id = ?
        """, (user_id,))
        
        user = cursor.fetchone()
        if not user:
            raise HTTPException(404, "Utilisateur non trouvé")
        
        user = dict(user)
        
        # Récupérer les documents
        cursor.execute("SELECT * FROM user_documents WHERE user_id = ?", (user_id,))
        user["documents"] = [dict(d) for d in cursor.fetchall()]
        
        # Si c'est un parent, récupérer les enfants
        if user["role"] == "parent":
            cursor.execute("SELECT * FROM enfants WHERE parent_id = ?", (user_id,))
            user["enfants"] = [dict(e) for e in cursor.fetchall()]
        
        # Si c'est un tuteur, récupérer les devoirs assignés
        if user["role"] in ["tuteur", "professeur"]:
            cursor.execute("""
                SELECT d.*, da.date_assignation, da.date_limite
                FROM devoirs d
                JOIN devoir_assignations da ON d.id = da.devoir_id
                WHERE da.tuteur_id = ?
                ORDER BY da.date_assignation DESC
            """, (user_id,))
            user["devoirs_assignes"] = [dict(d) for d in cursor.fetchall()]
        
        conn.close()
        
        return {"user": user}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération détails utilisateur: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/export/{table_name}")
async def export_table(table_name: str, format: str = "json", current_user = Depends(get_current_user)):
    """Exporte une table au format JSON ou CSV"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que la table existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        if not cursor.fetchone():
            raise HTTPException(404, f"Table {table_name} non trouvée")
        
        # Récupérer les données
        cursor.execute(f"SELECT * FROM {table_name} ORDER BY id")
        rows = cursor.fetchall()
        
        # Récupérer les noms des colonnes
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [col[1] for col in cursor.fetchall()]
        
        conn.close()
        
        # Formater les données
        data = []
        for row in rows:
            item = {}
            for idx, col in enumerate(columns):
                item[col] = row[idx]
            data.append(item)
        
        if format.lower() == "csv":
            # Créer CSV
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=columns)
            writer.writeheader()
            writer.writerows(data)
            
            csv_content = output.getvalue()
            
            return {
                "table": table_name,
                "format": "csv",
                "data": csv_content,
                "filename": f"{table_name}_{datetime.now().strftime('%Y%m%d')}.csv"
            }
        else:
            # JSON par défaut
            return {
                "table": table_name,
                "format": "json",
                "data": data,
                "count": len(data)
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur export table {table_name}: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/health")
async def health_check():
    """Vérification de santé"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        table_exists = cursor.fetchone()
        
        cursor.execute("SELECT COUNT(*) as count FROM users")
        count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            "status": "healthy",
            "database": "sqlite",
            "table_users_exists": table_exists is not None,
            "user_count": count,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        return {"status": "healthy", "database": "error", "error": str(e)}

# ============ ENDPOINTS D'AUTHENTIFICATION ============

@app.post("/auth/register", response_model=Token)
async def register(user: UserCreate):
    """Inscription d'un nouvel utilisateur (version JSON)"""
    logger.info(f"📝 Inscription: {user.email}")
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # Vérifier si l'email existe déjà
        cursor.execute("SELECT id FROM users WHERE email = ?", (user.email,))
        existing = cursor.fetchone()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Cet email est déjà utilisé"
            )
        
        # Hasher le mot de passe
        hashed_password = hash_password(user.password)
        
        # Insérer l'utilisateur
        cursor.execute("""
            INSERT INTO users (
                nom, prenom, email, telephone, password_hash, 
                adresse, ville, pays, profession, date_naissance, accept_terms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user.nom, user.prenom, user.email, user.telephone, hashed_password,
            user.adresse, user.ville, user.pays, user.profession, 
            user.date_naissance, user.accept_terms
        ))
        
        conn.commit()
        
        # Récupérer l'ID
        user_id = cursor.lastrowid
        logger.info(f"✅ Utilisateur créé avec ID: {user_id}")
        
        # Récupérer l'utilisateur créé
        cursor.execute("""
            SELECT id, nom, prenom, email, telephone, ville, pays, 
                   profession, is_active, created_at 
            FROM users WHERE id = ?
        """, (user_id,))
        
        row = cursor.fetchone()
        db_user = dict(row) if row else None
        
        # Créer le token JWT
        access_token = create_access_token(
            data={"sub": user.email, "user_id": user_id}
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": db_user
        }
        
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        logger.error(f"❌ Erreur inscription: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur serveur: {str(e)}"
        )
    finally:
        conn.close()

@app.post("/auth/login", response_model=Token)
async def login(user: UserLogin):
    """Connexion utilisateur"""
    logger.info(f"🔐 Connexion: {user.email}")
    
    # ⭐⭐ VÉRIFICATION SPÉCIALE POUR L'ADMIN ⭐⭐
    if user.email == "byamunguluc@gmail.com" and user.password == "taalimu2025":
        logger.info("👑 Connexion admin spécial détectée")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier si le compte existe
        cursor.execute("""
            SELECT id, nom, prenom, email, telephone, password_hash,
                   is_active, created_at, role
            FROM users WHERE email = ?
        """, (user.email,))
        
        row = cursor.fetchone()
        
        if not row:
            # Créer le compte admin s'il n'existe pas
            hashed_password = hash_password(user.password)
            cursor.execute("""
                INSERT INTO users (
                    nom, prenom, email, password_hash, 
                    accept_terms, role, is_active, is_verified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "Admin", "Super", user.email, hashed_password,
                True, "admin", True, True
            ))
            
            conn.commit()
            user_id = cursor.lastrowid
            
            cursor.execute("""
                SELECT id, nom, prenom, email, telephone,
                       is_active, created_at, role
                FROM users WHERE id = ?
            """, (user_id,))
            
            row = cursor.fetchone()
        
        db_user = dict(row)
        
        # Créer le token JWT
        access_token = create_access_token(
            data={
                "sub": user.email, 
                "user_id": db_user["id"],
                "role": "admin"  # Forcer le rôle admin
            }
        )
        
        # Préparer l'utilisateur pour la réponse
        user_response = {
            "id": db_user["id"],
            "nom": db_user["nom"],
            "prenom": db_user["prenom"],
            "email": db_user["email"],
            "telephone": db_user.get("telephone", ""),
            "is_active": db_user["is_active"],
            "created_at": db_user["created_at"],
            "role": "admin"  # S'assurer que role = admin
        }
        
        conn.close()
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_response
        }
    
    # Logique normale pour les autres utilisateurs
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT id, nom, prenom, email, telephone, password_hash,
                   is_active, created_at, role
            FROM users WHERE email = ?
        """, (user.email,))
        
        row = cursor.fetchone()
        if not row:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email ou mot de passe incorrect"
            )
        
        db_user = dict(row)
        
        # Vérifier le mot de passe
        if not verify_password(user.password, db_user["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Email ou mot de passe incorrect"
            )
        
        # Vérifier si le compte est actif
        if not db_user["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Compte désactivé"
            )
        
        # Créer le token JWT
        access_token = create_access_token(
            data={
                "sub": user.email, 
                "user_id": db_user["id"],
                "role": db_user.get("role", "user")
            }
        )
        
        # Préparer l'utilisateur pour la réponse
        user_response = {
            "id": db_user["id"],
            "nom": db_user["nom"],
            "prenom": db_user["prenom"],
            "email": db_user["email"],
            "telephone": db_user.get("telephone", ""),
            "is_active": db_user["is_active"],
            "created_at": db_user["created_at"]
        }
        
        # Ajouter les champs optionnels s'ils existent
        if "role" in db_user:
            user_response["role"] = db_user["role"]
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_response
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur connexion: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur serveur: {str(e)}"
        )
    finally:
        conn.close()

# ============ ENDPOINTS POUR DEVOIRS PARENTS ============

@app.post("/devoirs-parent/creer")
async def creer_devoir_parent(
    devoir_data: DevoirParentCreate,
    current_user = Depends(get_current_user)
):
    """Créer un devoir pour un parent"""
    try:
        # Vérifier que l'utilisateur est parent
        if current_user["role"] != "parent":
            raise HTTPException(403, "Seuls les parents peuvent créer des devoirs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que l'utilisateur est bien le parent de l'enfant
        cursor.execute("""
            SELECT id FROM enfants 
            WHERE id = ? AND parent_id = ?
        """, (devoir_data.enfant_id, current_user["id"]))
        
        enfant = cursor.fetchone()
        if not enfant:
            raise HTTPException(404, "Enfant non trouvé ou n'appartient pas à ce parent")
        
        # Insérer le devoir dans la table devoirs (qui correspond à devoir_parent)
        cursor.execute("""
            INSERT INTO devoirs (
                parent_id, enfant_id, titre, description, matiere,
                date_remise, niveau, type_devoir, priorite, statut
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            current_user["id"],  # Utiliser l'ID du parent connecté
            devoir_data.enfant_id,
            devoir_data.titre,
            devoir_data.description,
            devoir_data.matiere,
            devoir_data.date_remise,
            devoir_data.niveau,
            devoir_data.type_devoir,
            devoir_data.priorite,
            devoir_data.statut
        ))
        
        devoir_id = cursor.lastrowid
        conn.commit()
        
        # Récupérer le devoir créé avec les infos parent/enfant
        cursor.execute("""
            SELECT d.*, 
                   u.nom as parent_nom, u.prenom as parent_prenom,
                   e.nom as enfant_nom, e.prenom as enfant_prenom
            FROM devoirs d
            JOIN users u ON d.parent_id = u.id
            JOIN enfants e ON d.enfant_id = e.id
            WHERE d.id = ?
        """, (devoir_id,))
        
        row = cursor.fetchone()
        if row:
            devoir = dict(row)
        else:
            devoir = None
        
        conn.close()
        
        return {
            "success": True,
            "message": "Devoir créé avec succès",
            "devoir_id": devoir_id,
            "devoir": devoir
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur création devoir parent: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/devoirs-parent/parent/{parent_id}")
async def get_devoirs_par_parent(
    parent_id: int,
    current_user = Depends(get_current_user)
):
    """Récupérer tous les devoirs d'un parent"""
    try:
        # Vérifier que l'utilisateur accède à ses propres données
        if current_user["id"] != parent_id and current_user["role"] != "admin":
            raise HTTPException(403, "Accès non autorisé")
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT d.*, 
                   u.nom as parent_nom, u.prenom as parent_prenom,
                   e.nom as enfant_nom, e.prenom as enfant_prenom,
                   e.classe, e.age
            FROM devoirs d
            JOIN users u ON d.parent_id = u.id
            JOIN enfants e ON d.enfant_id = e.id
            WHERE d.parent_id = ?
            ORDER BY d.date_envoi DESC
        """, (parent_id,))
        
        rows = cursor.fetchall()
        devoirs = [dict(row) for row in rows]
        
        conn.close()
        
        return {
            "parent_id": parent_id,
            "devoirs": devoirs,
            "total": len(devoirs)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération devoirs parent: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/devoirs-parent/enfant/{enfant_id}")
async def get_devoirs_par_enfant(
    enfant_id: int,
    current_user = Depends(get_current_user)
):
    """Récupérer tous les devoirs d'un enfant"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que l'enfant appartient au parent connecté (sauf admin)
        if current_user["role"] != "admin":
            cursor.execute("""
                SELECT parent_id FROM enfants WHERE id = ?
            """, (enfant_id,))
            
            enfant = cursor.fetchone()
            if not enfant or dict(enfant)["parent_id"] != current_user["id"]:
                raise HTTPException(403, "Accès non autorisé")
        
        cursor.execute("""
            SELECT d.*, 
                   u.nom as parent_nom, u.prenom as parent_prenom,
                   e.nom as enfant_nom, e.prenom as enfant_prenom
            FROM devoirs d
            JOIN users u ON d.parent_id = u.id
            JOIN enfants e ON d.enfant_id = e.id
            WHERE d.enfant_id = ?
            ORDER BY d.date_remise ASC
        """, (enfant_id,))
        
        rows = cursor.fetchall()
        devoirs = [dict(row) for row in rows]
        
        conn.close()
        
        return {
            "enfant_id": enfant_id,
            "devoirs": devoirs,
            "total": len(devoirs)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération devoirs enfant: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/devoirs-parent/{devoir_id}")
async def get_devoir_parent_detail(
    devoir_id: int,
    current_user = Depends(get_current_user)
):
    """Récupérer les détails d'un devoir"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT d.*, 
                   u.nom as parent_nom, u.prenom as parent_prenom,
                   e.nom as enfant_nom, e.prenom as enfant_prenom,
                   e.age, e.classe, e.niveau as enfant_niveau
            FROM devoirs d
            JOIN users u ON d.parent_id = u.id
            JOIN enfants e ON d.enfant_id = e.id
            WHERE d.id = ?
        """, (devoir_id,))
        
        row = cursor.fetchone()
        if not row:
            raise HTTPException(404, "Devoir non trouvé")
        
        devoir = dict(row)
        
        # Vérifier les permissions (parent peut voir ses propres devoirs, admin peut tout voir)
        if current_user["role"] != "admin" and devoir["parent_id"] != current_user["id"]:
            raise HTTPException(403, "Accès non autorisé")
        
        # Récupérer les fichiers associés au devoir
        cursor.execute("""
            SELECT * FROM devoir_fichiers 
            WHERE devoir_id = ?
            ORDER BY uploaded_at
        """, (devoir_id,))
        
        fichiers_rows = cursor.fetchall()
        devoir["fichiers"] = [dict(f) for f in fichiers_rows]
        
        conn.close()
        
        return {
            "devoir": devoir,
            "nb_fichiers": len(devoir["fichiers"])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération détail devoir: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.put("/devoirs-parent/{devoir_id}")
async def update_devoir_parent(
    devoir_id: int,
    devoir_data: DevoirParentCreate,
    current_user = Depends(get_current_user)
):
    """Mettre à jour un devoir"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que le devoir existe et appartient au parent
        cursor.execute("""
            SELECT parent_id FROM devoirs WHERE id = ?
        """, (devoir_id,))
        
        devoir = cursor.fetchone()
        if not devoir:
            raise HTTPException(404, "Devoir non trouvé")
        
        if dict(devoir)["parent_id"] != current_user["id"] and current_user["role"] != "admin":
            raise HTTPException(403, "Accès non autorisé")
        
        # Mettre à jour le devoir
        cursor.execute("""
            UPDATE devoirs 
            SET titre = ?, description = ?, matiere = ?, 
                date_remise = ?, niveau = ?, type_devoir = ?,
                priorite = ?, statut = ?
            WHERE id = ?
        """, (
            devoir_data.titre,
            devoir_data.description,
            devoir_data.matiere,
            devoir_data.date_remise,
            devoir_data.niveau,
            devoir_data.type_devoir,
            devoir_data.priorite,
            devoir_data.statut,
            devoir_id
        ))
        
        conn.commit()
        
        # Récupérer le devoir mis à jour
        cursor.execute("""
            SELECT d.*, 
                   u.nom as parent_nom, u.prenom as parent_prenom,
                   e.nom as enfant_nom, e.prenom as enfant_prenom
            FROM devoirs d
            JOIN users u ON d.parent_id = u.id
            JOIN enfants e ON d.enfant_id = e.id
            WHERE d.id = ?
        """, (devoir_id,))
        
        row = cursor.fetchone()
        devoir_updated = dict(row) if row else None
        
        conn.close()
        
        return {
            "success": True,
            "message": "Devoir mis à jour avec succès",
            "devoir": devoir_updated
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur mise à jour devoir: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.delete("/devoirs-parent/{devoir_id}")
async def delete_devoir_parent(
    devoir_id: int,
    current_user = Depends(get_current_user)
):
    """Supprimer un devoir"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que le devoir existe et appartient au parent
        cursor.execute("""
            SELECT parent_id FROM devoirs WHERE id = ?
        """, (devoir_id,))
        
        devoir = cursor.fetchone()
        if not devoir:
            raise HTTPException(404, "Devoir non trouvé")
        
        if dict(devoir)["parent_id"] != current_user["id"] and current_user["role"] != "admin":
            raise HTTPException(403, "Accès non autorisé")
        
        # Supprimer le devoir
        cursor.execute("DELETE FROM devoirs WHERE id = ?", (devoir_id,))
        conn.commit()
        
        conn.close()
        
        return {
            "success": True,
            "message": "Devoir supprimé avec succès"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur suppression devoir: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")
@app.post("/auth/register-complete")
async def register_complete(
    # Données communes
    accountType: str = Form(...),
    nom: str = Form(...),
    prenom: str = Form(...),
    email: str = Form(...),
    telephone: str = Form(""),
    password: str = Form(...),
    accept_terms: bool = Form(False),
    
    # Données spécifiques (optionnelles)
    profession: str = Form(""),
    diplome: str = Form(""),
    experience: str = Form(""),
    etablissement: str = Form(""),
    matieres: str = Form("[]"),
    tarif_horaire: str = Form("0"),
    description: str = Form(""),
    disponibilites: str = Form("[]"),
    
    # Fichiers (uniquement pour tuteur)
    piece_identite: Optional[UploadFile] = File(None),
    diplome_certificat: Optional[UploadFile] = File(None),
    cv: Optional[UploadFile] = File(None),
    photo_profil: Optional[UploadFile] = File(None),
    casier_judiciaire: Optional[UploadFile] = File(None),
    video_presentation: Optional[UploadFile] = File(None)
):
    """Inscription complète pour tous les types de comptes (avec fichiers)"""
    logger.info(f"📝 Inscription {accountType}: {email}")
    
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        # 1. Validation basique
        if not accept_terms:
            raise HTTPException(400, "Vous devez accepter les conditions d'utilisation")
        
        # 2. Vérifier si l'email existe déjà
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing = cursor.fetchone()
        if existing:
            raise HTTPException(409, "Cet email est déjà utilisé")
        
        # 3. Hasher le mot de passe
        hashed_password = hash_password(password)
        
        # 4. Déterminer si c'est un tuteur
        is_teacher = accountType in ["tuteur"]
        
        # 5. Préparer les données d'insertion
        user_data = {
            "nom": nom,
            "prenom": prenom,
            "email": email,
            "telephone": telephone,
            "password_hash": hashed_password,
            "accept_terms": accept_terms,
            "role": accountType
        }
        
        # 6. Construire la requête SQL dynamique
        columns = ["nom", "prenom", "email", "telephone", "password_hash", "accept_terms", "role"]
        values = [nom, prenom, email, telephone, hashed_password, accept_terms, accountType]
        placeholders = ["?", "?", "?", "?", "?", "?", "?"]
        
        # Ajouter les champs spécifiques si c'est un tuteur
        if is_teacher:
            teacher_fields = {
                "profession": profession,
                "diplome": diplome,
                "experience": experience,
                "etablissement": etablissement,
                "matieres": matieres,
                "tarif_horaire": int(tarif_horaire) if tarif_horaire.isdigit() else 0,
                "description": description,
                "disponibilites": disponibilites
            }
            
            for field, value in teacher_fields.items():
                if value or field in ["tarif_horaire", "matieres", "disponibilites"]:
                    columns.append(field)
                    values.append(value)
                    placeholders.append("?")
        
        # 7. Insérer l'utilisateur
        sql = f"""
            INSERT INTO users ({", ".join(columns)})
            VALUES ({", ".join(placeholders)})
        """
        
        cursor.execute(sql, values)
        conn.commit()
        user_id = cursor.lastrowid
        
        # 8. Gérer les fichiers uploadés (uniquement pour tuteur)
        document_paths = {}
        if is_teacher:
            required_files = {
                "piece_identite": piece_identite,
                "diplome_certificat": diplome_certificat,
                "cv": cv,
                "photo_profil": photo_profil
            }
            
            for doc_type, file in required_files.items():
                if file and file.filename:
                    try:
                        file_path = await save_uploaded_file(file, user_id, doc_type)
                        document_paths[doc_type] = file_path
                        
                        cursor.execute("""
                            INSERT INTO user_documents 
                            (user_id, document_type, file_path, file_name, file_size, file_type)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            user_id, doc_type, file_path, file.filename, 
                            file.size, file.content_type
                        ))
                    except Exception as e:
                        logger.warning(f"⚠️ Erreur fichier {doc_type}: {str(e)}")
                        # On continue même si un fichier échoue
            
            # Fichiers optionnels
            optional_files = {
                "casier_judiciaire": casier_judiciaire,
                "video_presentation": video_presentation
            }
            
            for doc_type, file in optional_files.items():
                if file and file.filename:
                    try:
                        file_path = await save_uploaded_file(file, user_id, doc_type)
                        document_paths[doc_type] = file_path
                        
                        cursor.execute("""
                            INSERT INTO user_documents 
                            (user_id, document_type, file_path, file_name, file_size, file_type)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (user_id, doc_type, file_path, file.filename, 
                              file.size, file.content_type))
                    except Exception as e:
                        logger.warning(f"⚠️ Erreur fichier optionnel {doc_type}: {str(e)}")
        
        conn.commit()
        
        # 9. Créer le token JWT
        access_token = create_access_token(
            data={"sub": email, "user_id": user_id, "role": accountType}
        )
        
        # 10. Récupérer l'utilisateur créé
        cursor.execute("""
            SELECT id, nom, prenom, email, telephone, role, 
                   is_active, created_at
            FROM users WHERE id = ?
        """, (user_id,))
        
        row = cursor.fetchone()
        db_user = dict(row) if row else None
        
        # 11. Préparer la réponse
        response_data = {
            "success": True,
            "message": f"Inscription {accountType} réussie!",
            "access_token": access_token,
            "token_type": "bearer",
            "user": db_user,
            "user_id": user_id
        }
        
        # Ajouter des informations spécifiques selon le type
        if is_teacher:
            response_data["verification"] = {
                "status": "pending",
                "estimated_time": "24-48h",
                "documents_received": len(document_paths)
            }
        
        return JSONResponse(status_code=201, content=response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        logger.error(f"❌ Erreur inscription {accountType}: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")
    finally:
        conn.close()


@app.get("/tuteur/corrections/publiees")
async def get_corrections_publiees(
    current_user = Depends(get_current_user),
    statut: str = "corrigé",
    matiere: str = "",
    date_debut: str = "",
    date_fin: str = "",
    page: int = 1,
    per_page: int = 20
):
    """Récupérer les corrections publiées par le tuteur"""
    try:
        if current_user["role"] not in ["tuteur", "professeur"]:
            raise HTTPException(403, "Accès réservé aux tuteurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Requête pour les corrections avec toutes les informations
        base_query = """
            SELECT 
                c.*,
                
                -- Information du devoir
                d.titre as devoir_titre,
                d.description as devoir_description,
                d.matiere as devoir_matiere,
                d.niveau as devoir_niveau,
                d.date_remise,
                d.statut as devoir_statut,
                d.type_devoir,
                d.priorite,
                
                -- Information de l'enfant
                e.id as enfant_id,
                e.nom as enfant_nom,
                e.prenom as enfant_prenom,
                e.age as enfant_age,
                e.classe as enfant_classe,
                e.niveau as enfant_niveau,
                e.ecole as enfant_ecole,
                
                -- Information du parent
                p.id as parent_id,
                p.nom as parent_nom,
                p.prenom as parent_prenom,
                p.email as parent_email,
                p.telephone as parent_telephone,
                
                -- Information du tuteur
                t.nom as tuteur_nom,
                t.prenom as tuteur_prenom,
                t.email as tuteur_email,
                t.telephone as tuteur_telephone,
                
                -- Fichiers
                (SELECT COUNT(*) FROM correction_fichiers cf WHERE cf.correction_id = c.id) as nb_fichiers
                
            FROM corrections c
            JOIN devoirs d ON c.devoir_id = d.id
            JOIN enfants e ON d.enfant_id = e.id
            JOIN users p ON d.parent_id = p.id
            JOIN users t ON c.tuteur_id = t.id
            WHERE c.tuteur_id = ?
        """
        
        params = [current_user["id"]]
        
        # Filtre par statut
        if statut != "all":
            base_query += " AND c.status_correction = ?"
            params.append(statut)
        
        # Filtre par matière
        if matiere:
            base_query += " AND d.matiere LIKE ?"
            params.append(f"%{matiere}%")
        
        # Filtre par date
        if date_debut:
            base_query += " AND DATE(c.date_envoi) >= ?"
            params.append(date_debut)
        
        if date_fin:
            base_query += " AND DATE(c.date_envoi) <= ?"
            params.append(date_fin)
        
        # Compter le total
        count_query = f"SELECT COUNT(*) FROM ({base_query})"
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Ajouter ORDER BY et pagination
        offset = (page - 1) * per_page
        base_query += " ORDER BY c.date_envoi DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        cursor.execute(base_query, params)
        rows = cursor.fetchall()
        
        # Formater les résultats
        corrections = []
        for row in rows:
            correction = dict(row)
            
            # Formater les dates
            if correction["date_envoi"]:
                correction["date_envoi_formatted"] = correction["date_envoi"].split()[0]
                correction["date_envoi_time"] = correction["date_envoi"].split()[1][:5] if " " in str(correction["date_envoi"]) else ""
            
            if correction["date_correction"]:
                correction["date_correction_formatted"] = correction["date_correction"]
            
            # Récupérer les fichiers
            cursor.execute("""
                SELECT * FROM correction_fichiers 
                WHERE correction_id = ?
                ORDER BY uploaded_at
            """, (correction["id"],))
            
            fichiers_rows = cursor.fetchall()
            correction["fichiers"] = [dict(f) for f in fichiers_rows]
            
            # Couleur selon la note
            note = correction["note"]
            if note >= 16:
                correction["note_color"] = "#10B981"
                correction["note_label"] = "Excellent"
            elif note >= 12:
                correction["note_color"] = "#F59E0B"
                correction["note_label"] = "Bon"
            elif note >= 8:
                correction["note_color"] = "#F59E0B"
                correction["note_label"] = "Moyen"
            else:
                correction["note_color"] = "#EF4444"
                correction["note_label"] = "À améliorer"
            
            corrections.append(correction)
        
        # Statistiques
        cursor.execute("""
            SELECT 
                COUNT(*) as total_corrections,
                AVG(note) as note_moyenne,
                SUM(temps_passe) as temps_total,
                COUNT(DISTINCT d.matiere) as matieres_differentes,
                COUNT(DISTINCT d.parent_id) as parents_differents
            FROM corrections c
            JOIN devoirs d ON c.devoir_id = d.id
            WHERE c.tuteur_id = ?
        """, (current_user["id"],))
        
        stats_row = cursor.fetchone()
        stats = dict(stats_row) if stats_row else {}
        
        conn.close()
        
        return {
            "corrections": corrections,
            "stats": stats,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": (total + per_page - 1) // per_page
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération corrections publiées: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/tuteur/corrections/{correction_id}/detail-complet")
async def get_correction_detail_complet(
    correction_id: int,
    current_user = Depends(get_current_user)
):
    """Récupérer le détail complet d'une correction avec tous les champs"""
    try:
        if current_user["role"] not in ["tuteur", "professeur"]:
            raise HTTPException(403, "Accès réservé aux tuteurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Récupérer la correction avec TOUS les champs
        cursor.execute("""
            SELECT 
                c.*,
                
                -- Information du devoir
                d.titre as devoir_titre,
                d.description as devoir_description,
                d.matiere as devoir_matiere,
                d.niveau as devoir_niveau,
                d.date_remise,
                d.statut as devoir_statut,
                d.type_devoir,
                d.priorite,
                d.notes_tuteur as devoir_notes_tuteur,
                
                -- Information de l'enfant
                e.id as enfant_id,
                e.nom as enfant_nom,
                e.prenom as enfant_prenom,
                e.age as enfant_age,
                e.classe as enfant_classe,
                e.niveau as enfant_niveau,
                e.ecole as enfant_ecole,
                
                -- Information du parent
                p.id as parent_id,
                p.nom as parent_nom,
                p.prenom as parent_prenom,
                p.email as parent_email,
                p.telephone as parent_telephone,
                p.adresse as parent_adresse,
                p.ville as parent_ville,
                
                -- Information du tuteur
                t.nom as tuteur_nom,
                t.prenom as tuteur_prenom,
                t.email as tuteur_email,
                t.telephone as tuteur_telephone,
                t.diplome as tuteur_diplome,
                t.experience as tuteur_experience,
                t.matieres as tuteur_matieres
                
            FROM corrections c
            JOIN devoirs d ON c.devoir_id = d.id
            JOIN enfants e ON d.enfant_id = e.id
            JOIN users p ON d.parent_id = p.id
            JOIN users t ON c.tuteur_id = t.id
            WHERE c.id = ? AND c.tuteur_id = ?
        """, (correction_id, current_user["id"]))
        
        row = cursor.fetchone()
        if not row:
            raise HTTPException(404, "Correction non trouvée ou accès non autorisé")
        
        correction = dict(row)
        
        # Récupérer les fichiers
        cursor.execute("""
            SELECT * FROM correction_fichiers 
            WHERE correction_id = ?
            ORDER BY uploaded_at
        """, (correction_id,))
        
        fichiers_rows = cursor.fetchall()
        correction["fichiers"] = [dict(f) for f in fichiers_rows]
        
        # Récupérer les fichiers du devoir original
        cursor.execute("""
            SELECT * FROM devoir_fichiers 
            WHERE devoir_id = ?
            ORDER BY uploaded_at
        """, (correction["devoir_id"],))
        
        devoir_fichiers_rows = cursor.fetchall()
        correction["devoir_fichiers"] = [dict(f) for f in devoir_fichiers_rows]
        
        # Formater les matières du tuteur
        if correction["tuteur_matieres"]:
            try:
                correction["tuteur_matieres_list"] = json.loads(correction["tuteur_matieres"])
            except:
                correction["tuteur_matieres_list"] = []
        else:
            correction["tuteur_matieres_list"] = []
        
        # Formater les dates
        if correction["date_envoi"]:
            correction["date_envoi_formatted"] = correction["date_envoi"].split()[0] if correction["date_envoi"] else ""
            correction["date_envoi_time"] = correction["date_envoi"].split()[1][:5] if " " in str(correction["date_envoi"]) else ""
        
        # Couleur selon la note
        note = correction["note"]
        if note >= 16:
            correction["note_color"] = "#10B981"
            correction["note_label"] = "Excellent"
        elif note >= 12:
            correction["note_color"] = "#F59E0B"
            correction["note_label"] = "Bon"
        elif note >= 8:
            correction["note_color"] = "#F59E0B"
            correction["note_label"] = "Moyen"
        else:
            correction["note_color"] = "#EF4444"
            correction["note_label"] = "À améliorer"
        
        conn.close()
        
        return {
            "correction": correction,
            "nb_fichiers": len(correction["fichiers"]),
            "nb_fichiers_devoir": len(correction["devoir_fichiers"])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération détail correction complet: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")
# ============ ENDPOINTS PROTÉGÉS ============

@app.get("/auth/me")
async def get_current_user_endpoint(current_user = Depends(get_current_user)):
    """Récupère l'utilisateur connecté"""
    return current_user

# ============ ENDPOINTS POUR LES DEVOIRS ============

@app.post("/devoirs/creer")
async def creer_devoir(
    devoir_data: DevoirCreate,
    current_user = Depends(get_current_user)
):
    """Créer un nouveau devoir (pour parent)"""
    try:
        # Vérifier que l'utilisateur est parent
        if current_user["role"] != "parent":
            raise HTTPException(403, "Seuls les parents peuvent créer des devoirs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que l'enfant appartient au parent
        cursor.execute("SELECT id FROM enfants WHERE id = ? AND parent_id = ?", 
                      (devoir_data.enfant_id, current_user["id"]))
        enfant = cursor.fetchone()
        if not enfant:
            raise HTTPException(404, "Enfant non trouvé ou n'appartient pas à ce parent")
        
        # Insérer le devoir
        cursor.execute("""
            INSERT INTO devoirs (
                parent_id, enfant_id, titre, description, matiere,
                date_remise, niveau, type_devoir, priorite, statut
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            current_user["id"],
            devoir_data.enfant_id,
            devoir_data.titre,
            devoir_data.description,
            devoir_data.matiere,
            devoir_data.date_remise,
            devoir_data.niveau,
            devoir_data.type_devoir,
            devoir_data.priorite,
            devoir_data.statut
        ))
        
        devoir_id = cursor.lastrowid
        conn.commit()
        
        # Récupérer le devoir créé
        cursor.execute("""
            SELECT d.*, 
                   u.nom as parent_nom, u.prenom as parent_prenom,
                   e.nom as enfant_nom, e.prenom as enfant_prenom
            FROM devoirs d
            JOIN users u ON d.parent_id = u.id
            JOIN enfants e ON d.enfant_id = e.id
            WHERE d.id = ?
        """, (devoir_id,))
        
        row = cursor.fetchone()
        if row:
            devoir = dict(row)
        else:
            devoir = None
        
        conn.close()
        
        return {
            "success": True,
            "message": "Devoir créé avec succès",
            "devoir_id": devoir_id,
            "devoir": devoir
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur création devoir: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")
    
# ============ ENDPOINTS ADMIN ============

@app.get("/admin/stats")
async def get_admin_stats(current_user = Depends(get_current_user)):
    """Récupère les statistiques pour le tableau de bord admin"""
    try:
        # Vérifier que l'utilisateur est admin
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Nombre total d'utilisateurs
        cursor.execute("SELECT COUNT(*) as total FROM users")
        total_users = cursor.fetchone()["total"]
        
        # Utilisateurs actifs aujourd'hui
        cursor.execute("""
            SELECT COUNT(*) as active_today 
            FROM users 
            WHERE DATE(created_at) = DATE('now') AND is_active = TRUE
        """)
        active_today = cursor.fetchone()["active_today"]
        
        # Utilisateurs en attente de vérification
        cursor.execute("""
            SELECT COUNT(*) as pending_verifications 
            FROM users 
            WHERE verification_status = 'pending' 
            AND role IN ('tuteur')
        """)
        pending_verifications = cursor.fetchone()["pending_verifications"]
        
        # Nombre total de devoirs
        cursor.execute("SELECT COUNT(*) as total_devoirs FROM devoirs")
        total_devoirs = cursor.fetchone()["total_devoirs"]
        
        # Devoirs en attente
        cursor.execute("""
            SELECT COUNT(*) as pending_devoirs 
            FROM devoirs 
            WHERE statut IN ('envoyé', 'assigné')
        """)
        pending_devoirs = cursor.fetchone()["pending_devoirs"]
        
        # Revenus (simulés pour l'instant)
        # Vous devrez créer une table des paiements plus tard
        total_revenue = 1250000
        revenue_growth = 24.5
        
        conn.close()
        
        return {
            "totalUsers": total_users,
            "activeUsers": active_today,
            "pendingVerifications": pending_verifications,
            "totalDevoirs": total_devoirs,
            "devoirsPending": pending_devoirs,
            "totalRevenue": total_revenue,
            "revenueGrowth": revenue_growth
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur stats admin: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/users/recent")
async def get_recent_users(current_user = Depends(get_current_user)):
    """Récupère les utilisateurs récents"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                id, nom, prenom, email, telephone, role as type,
                is_active as status, created_at,
                CASE 
                    WHEN is_active = TRUE THEN 'active'
                    WHEN verification_status = 'pending' THEN 'pending'
                    ELSE 'inactive'
                END as status_label
            FROM users 
            ORDER BY created_at DESC 
            LIMIT 10
        """)
        
        rows = cursor.fetchall()
        users = []
        
        for row in rows:
            user_data = dict(row)
            user_data["createdAt"] = user_data.pop("created_at").split()[0]
            user_data["status"] = user_data["status_label"]
            users.append(user_data)
        
        conn.close()
        
        return {"users": users}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération utilisateurs récents: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/verifications/pending")
async def get_pending_verifications(current_user = Depends(get_current_user)):
    """Récupère les vérifications en attente"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                u.id as userId,
                u.nom, u.prenom, u.email, u.role as type,
                u.created_at as submittedAt,
                COUNT(ud.id) as documents
            FROM users u
            LEFT JOIN user_documents ud ON u.id = ud.user_id
            WHERE u.verification_status = 'pending'
            AND u.role IN ('tuteur')
            GROUP BY u.id
            ORDER BY u.created_at DESC
        """)
        
        rows = cursor.fetchall()
        verifications = []
        
        for row in rows:
            verif_data = dict(row)
            verif_data["submittedAt"] = verif_data["submittedAt"].split()[0]
            verifications.append(verif_data)
        
        conn.close()
        
        return {"verifications": verifications}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération vérifications: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")
@app.post("/devoirs/{devoir_id}/upload-fichier")
async def upload_fichier_devoir(
    devoir_id: int,
    fichier: UploadFile = File(...),
    current_user = Depends(get_current_user)
):
    """Uploader un fichier pour un devoir"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que le devoir existe et appartient à l'utilisateur
        cursor.execute("""
            SELECT parent_id FROM devoirs WHERE id = ?
        """, (devoir_id,))
        
        devoir = cursor.fetchone()
        if not devoir:
            raise HTTPException(404, "Devoir non trouvé")
        
        # Vérifier les permissions
        devoir_dict = dict(devoir)
        if devoir_dict["parent_id"] != current_user["id"] and current_user["role"] != "admin":
            raise HTTPException(403, "Vous n'avez pas accès à ce devoir")
        
        # Vérifier la taille du fichier (max 100MB)
        MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
        content = await fichier.read()
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(413, "Fichier trop volumineux. Maximum 100MB")
        
        # Créer le dossier uploads/devoirs s'il n'existe pas
        upload_subdir = os.path.join(UPLOAD_DIR, "devoirs")
        os.makedirs(upload_subdir, exist_ok=True)
        
        # Générer un nom de fichier sécurisé
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_ext = os.path.splitext(fichier.filename)[1]
        safe_filename = f"devoir_{devoir_id}_{timestamp}{file_ext}"
        file_path = os.path.join(upload_subdir, safe_filename)
        
        # Sauvegarder le fichier
        with open(file_path, "wb") as buffer:
            buffer.write(content)
        
        # Déterminer le type de fichier
        file_type = fichier.content_type or "application/octet-stream"
        
        # Enregistrer dans la base
        cursor.execute("""
            INSERT INTO devoir_fichiers 
            (devoir_id, nom_fichier, chemin_fichier, type_fichier, taille)
            VALUES (?, ?, ?, ?, ?)
        """, (
            devoir_id,
            fichier.filename,
            file_path,
            file_type,
            len(content)
        ))
        
        conn.commit()
        fichier_id = cursor.lastrowid
        
        conn.close()
        
        return {
            "success": True,
            "message": "Fichier uploadé avec succès",
            "fichier_id": fichier_id,
            "nom_original": fichier.filename,
            "chemin_fichier": file_path,
            "taille": len(content),
            "type_fichier": file_type
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur upload fichier devoir: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/devoirs/{devoir_id}/fichiers")
async def get_fichiers_devoir(
    devoir_id: int,
    current_user = Depends(get_current_user)
):
    """Récupérer tous les fichiers d'un devoir"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que le devoir existe
        cursor.execute("""
            SELECT d.*, p.nom as parent_nom, p.prenom as parent_prenom
            FROM devoirs d
            JOIN users p ON d.parent_id = p.id
            WHERE d.id = ?
        """, (devoir_id,))
        
        devoir = cursor.fetchone()
        if not devoir:
            raise HTTPException(404, "Devoir non trouvé")
        
        devoir = dict(devoir)
        
        # Vérifier les permissions
        if devoir["parent_id"] != current_user["id"] and current_user["role"] != "admin":
            raise HTTPException(403, "Vous n'avez pas accès à ce devoir")
        
        # Récupérer les fichiers
        cursor.execute("""
            SELECT * FROM devoir_fichiers 
            WHERE devoir_id = ?
            ORDER BY uploaded_at
        """, (devoir_id,))
        
        fichiers_rows = cursor.fetchall()
        fichiers = [dict(f) for f in fichiers_rows]
        
        conn.close()
        
        return {
            "devoir_id": devoir_id,
            "fichiers": fichiers,
            "total": len(fichiers)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération fichiers devoir: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.delete("/devoirs/fichiers/{fichier_id}")
async def delete_fichier_devoir(
    fichier_id: int,
    current_user = Depends(get_current_user)
):
    """Supprimer un fichier d'un devoir"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Récupérer le fichier et vérifier les permissions
        cursor.execute("""
            SELECT df.*, d.parent_id 
            FROM devoir_fichiers df
            JOIN devoirs d ON df.devoir_id = d.id
            WHERE df.id = ?
        """, (fichier_id,))
        
        fichier = cursor.fetchone()
        if not fichier:
            raise HTTPException(404, "Fichier non trouvé")
        
        fichier = dict(fichier)
        
        # Vérifier les permissions
        if fichier["parent_id"] != current_user["id"] and current_user["role"] != "admin":
            raise HTTPException(403, "Vous n'avez pas accès à ce fichier")
        
        # Supprimer le fichier physique
        if os.path.exists(fichier["chemin_fichier"]):
            os.remove(fichier["chemin_fichier"])
        
        # Supprimer de la base de données
        cursor.execute("DELETE FROM devoir_fichiers WHERE id = ?", (fichier_id,))
        conn.commit()
        
        conn.close()
        
        return {
            "success": True,
            "message": "Fichier supprimé avec succès"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur suppression fichier: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/tuteur/corrections")
async def get_corrections_tuteur(
    tuteur_id: int = None,  # Optionnel, sinon récupérer du token
    statut: str = "all",
    matiere: str = "",
    date_debut: str = "",
    date_fin: str = "",
    page: int = 1,
    per_page: int = 20,
    current_user = Depends(get_current_user)
):
    """Récupérer les corrections d'un tuteur (alias pour /tuteur/mes-corrections)"""
    try:
        # Vérifier que l'utilisateur est tuteur
        if current_user["role"] not in ["tuteur", "professeur"]:
            raise HTTPException(403, "Accès réservé aux tuteurs")
        
        # Si tuteur_id n'est pas fourni, utiliser l'ID du tuteur connecté
        if not tuteur_id:
            tuteur_id = current_user["id"]
        else:
            # Vérifier que le tuteur accède à ses propres données
            if tuteur_id != current_user["id"] and current_user["role"] != "admin":
                raise HTTPException(403, "Accès non autorisé")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Requête similaire à /tuteur/mes-corrections - CORRIGÉE
        base_query = """
            SELECT 
                c.id,
                c.devoir_id,
                c.note,  # Explicitly use c.note
                c.commentaires,
                c.remarques,
                c.recommandations,
                c.temps_passe,
                c.difficulte,
                c.status_correction,
                c.date_correction,
                c.date_envoi,
                c.type_correction,
                c.format_explication,
                c.niveau_detail,
                c.methode_resolution,
                c.points_cles,
                c.erreurs_communes,
                c.conseils_pratiques,
                c.ressources_complementaires,
                c.temps_estime_eleve,
                c.valide_par_admin,
                
                -- Information du devoir
                d.titre as devoir_titre,
                d.description as devoir_description,
                d.matiere as devoir_matiere,
                d.niveau as devoir_niveau,
                d.date_remise,
                d.statut as devoir_statut,
                
                -- Information de l'enfant
                e.id as enfant_id,
                e.nom as enfant_nom,
                e.prenom as enfant_prenom,
                e.age as enfant_age,
                e.classe as enfant_classe,
                e.niveau as enfant_niveau,
                
                -- Information du parent
                p.id as parent_id,
                p.nom as parent_nom,
                p.prenom as parent_prenom,
                p.email as parent_email,
                
                -- Nombre de fichiers
                (SELECT COUNT(*) FROM correction_fichiers cf WHERE cf.correction_id = c.id) as nb_fichiers
                
            FROM corrections c
            JOIN devoirs d ON c.devoir_id = d.id
            JOIN enfants e ON d.enfant_id = e.id
            JOIN users p ON d.parent_id = p.id
            WHERE c.tuteur_id = ?
        """
        
        params = [tuteur_id]
        
        # Filtres
        filters = []
        
        if statut != "all":
            filters.append("c.status_correction = ?")
            params.append(statut)
        
        if matiere:
            filters.append("d.matiere LIKE ?")
            params.append(f"%{matiere}%")
        
        if date_debut:
            filters.append("DATE(c.date_envoi) >= ?")
            params.append(date_debut)
        
        if date_fin:
            filters.append("DATE(c.date_envoi) <= ?")
            params.append(date_fin)
        
        if filters:
            base_query += " AND " + " AND ".join(filters)
        
        # Compter le total
        count_query = f"SELECT COUNT(*) FROM ({base_query})"
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Ajouter ORDER BY et pagination
        offset = (page - 1) * per_page
        base_query += " ORDER BY c.date_envoi DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        cursor.execute(base_query, params)
        rows = cursor.fetchall()
        
        # Formater les résultats
        corrections = []
        for row in rows:
            correction = dict(row)
            
            # Formater les dates
            if correction["date_envoi"]:
                correction["date_envoi_formatted"] = correction["date_envoi"].split()[0]
                correction["date_envoi_time"] = correction["date_envoi"].split()[1][:5] if " " in str(correction["date_envoi"]) else ""
            
            if correction["date_correction"]:
                correction["date_correction_formatted"] = correction["date_correction"]
            
            # Récupérer les fichiers
            cursor.execute("""
                SELECT * FROM correction_fichiers 
                WHERE correction_id = ?
                ORDER BY uploaded_at
            """, (correction["id"],))
            
            fichiers_rows = cursor.fetchall()
            correction["fichiers"] = [dict(f) for f in fichiers_rows]
            
            # Couleur selon la note
            note = correction.get("note", 0) or 0
            if note >= 16:
                correction["note_color"] = "#10B981"  # Vert
                correction["note_label"] = "Excellent"
            elif note >= 12:
                correction["note_color"] = "#F59E0B"  # Orange
                correction["note_label"] = "Bon"
            elif note >= 8:
                correction["note_color"] = "#F59E0B"  # Orange clair
                correction["note_label"] = "Moyen"
            else:
                correction["note_color"] = "#EF4444"  # Rouge
                correction["note_label"] = "À améliorer"
            
            corrections.append(correction)
        
        # Statistiques - CORRIGÉ
        cursor.execute("""
            SELECT 
                COUNT(*) as total_corrections,
                AVG(c.note) as note_moyenne,  # Explicitly use c.note
                SUM(c.temps_passe) as temps_total,
                COUNT(DISTINCT d.matiere) as matieres_differentes,
                COUNT(DISTINCT d.parent_id) as parents_differents
            FROM corrections c
            JOIN devoirs d ON c.devoir_id = d.id
            WHERE c.tuteur_id = ?
        """, (tuteur_id,))
        
        stats_row = cursor.fetchone()
        stats = dict(stats_row) if stats_row else {}
        
        conn.close()
        
        return {
            "corrections": corrections,
            "stats": stats,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": (total + per_page - 1) // per_page
            },
            "tuteur_id": tuteur_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération corrections tuteur: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")
@app.get("/tuteur/corrections/stats")
async def get_corrections_stats_tuteur(
    tuteur_id: int = None,
    current_user = Depends(get_current_user)
):
    """Récupère les statistiques des corrections d'un tuteur"""
    try:
        if current_user["role"] not in ["tuteur", "professeur"]:
            raise HTTPException(403, "Accès réservé aux tuteurs")
        
        # Utiliser l'ID du tuteur connecté
        if not tuteur_id:
            tuteur_id = current_user["id"]
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Statistiques générales
        cursor.execute("""
            SELECT 
                COUNT(*) as total_corrections,
                COUNT(DISTINCT devoir_id) as devoirs_corriges,
                AVG(note) as note_moyenne,
                SUM(temps_passe) as temps_total_heures,
                MIN(date_envoi) as premiere_correction,
                MAX(date_envoi) as derniere_correction
            FROM corrections 
            WHERE tuteur_id = ?
        """, (tuteur_id,))
        
        stats_general = dict(cursor.fetchone())
        
        # Statistiques par matière
        cursor.execute("""
            SELECT 
                d.matiere,
                COUNT(*) as nombre_corrections,
                AVG(c.note) as note_moyenne,
                SUM(c.temps_passe) as temps_total
            FROM corrections c
            JOIN devoirs d ON c.devoir_id = d.id
            WHERE c.tuteur_id = ?
            GROUP BY d.matiere
            ORDER BY nombre_corrections DESC
        """, (tuteur_id,))
        
        stats_matiere = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "general": stats_general,
            "par_matiere": stats_matiere,
            "tuteur_id": tuteur_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération stats corrections: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/tuteur/travaux-corriges")
async def get_travaux_corriges_tuteur(
    tuteur_id: int = None,
    statut: str = "publié",
    matiere: str = "",
    current_user = Depends(get_current_user)
):
    """Récupérer les travaux corrigés généraux d'un tuteur"""
    try:
        if current_user["role"] not in ["tuteur", "professeur"]:
            raise HTTPException(403, "Accès réservé aux tuteurs")
        
        # Si tuteur_id n'est pas fourni, utiliser l'ID du tuteur connecté
        if not tuteur_id:
            tuteur_id = current_user["id"]
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Construire la requête
        base_query = """
            SELECT 
                tc.*,
                u.nom as tuteur_nom,
                u.prenom as tuteur_prenom,
                u.email as tuteur_email,
                (SELECT COUNT(*) FROM travail_corrige_fichiers tcf 
                 WHERE tcf.travail_id = tc.id) as nb_fichiers
            FROM travaux_corriges tc
            JOIN users u ON tc.tuteur_id = u.id
            WHERE tc.tuteur_id = ?
        """
        
        params = [tuteur_id]
        
        if statut != "all":
            base_query += " AND tc.statut = ?"
            params.append(statut)
        
        if matiere:
            base_query += " AND tc.matiere LIKE ?"
            params.append(f"%{matiere}%")
        
        base_query += " ORDER BY tc.created_at DESC"
        
        cursor.execute(base_query, params)
        rows = cursor.fetchall()
        
        travaux = []
        for row in rows:
            travail = dict(row)
            
            # Formater les dates
            if travail["created_at"]:
                travail["created_at_formatted"] = travail["created_at"].split()[0]
            
            # Récupérer les fichiers
            cursor.execute("""
                SELECT * FROM travail_corrige_fichiers 
                WHERE travail_id = ?
                ORDER BY uploaded_at
            """, (travail["id"],))
            
            fichiers_rows = cursor.fetchall()
            travail["fichiers"] = [dict(f) for f in fichiers_rows]
            
            travaux.append(travail)
        
        conn.close()
        
        return {
            "travaux": travaux,
            "total": len(travaux),
            "tuteur_id": tuteur_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération travaux corrigés: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/activities")
async def get_recent_activities(current_user = Depends(get_current_user)):
    """Récupère les activités récentes"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Pour l'instant, on simule les activités
        # Vous devrez créer une table d'activités plus tard
        activities = [
            {
                "id": 1,
                "action": "user_registered",
                "user": "Jean Dupont",
                "type": "parent",
                "timestamp": "Il y a 5 min",
                "details": "Nouvelle inscription"
            },
            {
                "id": 2,
                "action": "devoir_submitted",
                "user": "Marie Curie",
                "type": "eleve",
                "timestamp": "Il y a 15 min",
                "details": "Devoir de Mathématiques"
            },
            
        ]
        
        conn.close()
        
        return {"activities": activities}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération activités: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/revenue")
async def get_revenue_data(current_user = Depends(get_current_user)):
    """Récupère les données de revenus"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        # Données simulées pour l'instant
        revenue_data = [
            {"month": "Jan", "revenue": 850000},
            {"month": "Fév", "revenue": 920000},
            {"month": "Mar", "revenue": 1250000},
            {"month": "Avr", "revenue": 980000},
            {"month": "Mai", "revenue": 1100000},
            {"month": "Jun", "revenue": 1350000}
        ]
        
        return {"revenue": revenue_data}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération revenus: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.post("/admin/verifications/{user_id}/approve")
async def approve_verification(user_id: int, current_user = Depends(get_current_user)):
    """Approuve la vérification d'un utilisateur"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE users 
            SET verification_status = 'approved', 
                is_verified = TRUE,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (user_id,))
        
        conn.commit()
        
        conn.close()
        
        return {"success": True, "message": "Vérification approuvée"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur approbation vérification: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.post("/admin/verifications/{user_id}/reject")
async def reject_verification(user_id: int, current_user = Depends(get_current_user)):
    """Rejette la vérification d'un utilisateur"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE users 
            SET verification_status = 'rejected', 
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (user_id,))
        
        conn.commit()
        
        conn.close()
        
        return {"success": True, "message": "Vérification rejetée"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur rejet vérification: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

# Ajoutez cette fonction pour créer un admin par défaut
def create_default_admin():
    """Crée un compte administrateur par défaut"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        admin_email = "admin@taalimu.com"
        admin_password = "Admin123@"  # Mot de passe par défaut
        
        # Vérifier si l'admin existe déjà
        cursor.execute("SELECT id FROM users WHERE email = ?", (admin_email,))
        existing = cursor.fetchone()
        
        if not existing:
            hashed_password = hash_password(admin_password)
            
            cursor.execute("""
                INSERT INTO users (
                    nom, prenom, email, password_hash, 
                    accept_terms, role, is_active, is_verified
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "Administrateur", 
                "Super", 
                admin_email, 
                hashed_password,
                True, 
                "admin", 
                True, 
                True
            ))
            
            conn.commit()
            logger.info(f"✅ Compte admin créé: {admin_email}")
        else:
            logger.info(f"✅ Compte admin existe déjà: {admin_email}")
            
    except Exception as e:
        logger.error(f"❌ Erreur création admin: {str(e)}")
    finally:
        conn.close()

def create_specific_admin():
    """Crée le compte admin spécifique"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        admin_email = "byamunguluc@gmail.com"
        admin_password = "taalimu2025"
        
        # Vérifier si l'admin existe déjà
        cursor.execute("SELECT id FROM users WHERE email = ?", (admin_email,))
        existing = cursor.fetchone()
        
        if not existing:
            hashed_password = hash_password(admin_password)
            
            cursor.execute("""
                INSERT INTO users (
                    nom, prenom, email, password_hash, 
                    accept_terms, role, is_active, is_verified,
                    telephone, adresse, ville, pays
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                "Admin", 
                "Super", 
                admin_email, 
                hashed_password,
                True, 
                "admin", 
                True, 
                True,
                "+243 81 000 0000",
                "Kinshasa",
                "Kinshasa",
                "RDC"
            ))
            
            conn.commit()
            logger.info(f"✅ Compte admin spécifique créé: {admin_email}")
        else:
            logger.info(f"✅ Compte admin spécifique existe déjà: {admin_email}")
            
            # Mettre à jour le mot de passe au cas où
            hashed_password = hash_password(admin_password)
            cursor.execute("""
                UPDATE users 
                SET password_hash = ?, role = 'admin', is_active = TRUE, is_verified = TRUE
                WHERE email = ?
            """, (hashed_password, admin_email))
            conn.commit()
            
    except Exception as e:
        logger.error(f"❌ Erreur création admin spécifique: {str(e)}")
    finally:
        conn.close()

# Modifiez la fonction startup_event pour créer l'admin par défaut
@app.on_event("startup")
async def startup_event():
    logger.info("🚀 Démarrage API Taalimu avec SQLite...")
    init_db()
    create_specific_admin()  # Crée l'admin avec les identifiants spécifiques
    create_default_admin()   # Gardez aussi l'autre admin si vous voulez
    logger.info("✅ API prête!")
@app.post("/devoirs/{devoir_id}/upload-fichier")
async def upload_fichier_devoir(
    devoir_id: int,
    fichier: UploadFile = File(...),
    current_user = Depends(get_current_user)
):
    """Uploader un fichier pour un devoir"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que le devoir existe et appartient à l'utilisateur
        cursor.execute("""
            SELECT parent_id FROM devoirs WHERE id = ?
        """, (devoir_id,))
        
        devoir = cursor.fetchone()
        if not devoir:
            raise HTTPException(404, "Devoir non trouvé")
        
        if dict(devoir)["parent_id"] != current_user["id"]:
            raise HTTPException(403, "Vous n'avez pas accès à ce devoir")
        
        # Sauvegarder le fichier
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_ext = os.path.splitext(fichier.filename)[1]
        safe_filename = f"devoir_{devoir_id}_{timestamp}{file_ext}"
        file_path = os.path.join(UPLOAD_DIR, "devoirs", safe_filename)
        
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        
        with open(file_path, "wb") as buffer:
            content = await fichier.read()
            buffer.write(content)
        
        # Enregistrer dans la base
        cursor.execute("""
            INSERT INTO devoir_fichiers 
            (devoir_id, nom_fichier, chemin_fichier, type_fichier, taille)
            VALUES (?, ?, ?, ?, ?)
        """, (
            devoir_id,
            fichier.filename,
            file_path,
            fichier.content_type,
            len(content)
        ))
        
        conn.commit()
        fichier_id = cursor.lastrowid
        
        conn.close()
        
        return {
            "success": True,
            "message": "Fichier uploadé avec succès",
            "fichier_id": fichier_id,
            "chemin_fichier": file_path,
            "nom_original": fichier.filename
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur upload fichier devoir: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/parents/{parent_id}/devoirs")
async def get_devoirs_parent(
    parent_id: int,
    current_user = Depends(get_current_user)
):
    """Récupérer tous les devoirs d'un parent"""
    try:
        if current_user["id"] != parent_id:
            raise HTTPException(403, "Accès non autorisé")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Récupérer les devoirs avec informations enfants
        cursor.execute("""
            SELECT d.*, 
                   e.nom as enfant_nom, e.prenom as enfant_prenom, e.classe,
                   COUNT(df.id) as nb_fichiers
            FROM devoirs d
            JOIN enfants e ON d.enfant_id = e.id
            LEFT JOIN devoir_fichiers df ON d.id = df.devoir_id
            WHERE d.parent_id = ?
            GROUP BY d.id
            ORDER BY d.date_envoi DESC
        """, (parent_id,))
        
        rows = cursor.fetchall()
        devoirs = []
        
        for row in rows:
            devoir = dict(row)
            
            # Récupérer les fichiers pour ce devoir
            cursor.execute("""
                SELECT id, nom_fichier, type_fichier, taille, uploaded_at
                FROM devoir_fichiers 
                WHERE devoir_id = ?
                ORDER BY uploaded_at
            """, (devoir["id"],))
            
            fichiers_rows = cursor.fetchall()
            devoir["fichiers"] = [dict(f) for f in fichiers_rows]
            
            devoirs.append(devoir)
        
        conn.close()
        
        return {
            "parent_id": parent_id,
            "devoirs": devoirs,
            "total": len(devoirs)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération devoirs: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/devoirs/{devoir_id}")
async def get_devoir_detail(
    devoir_id: int,
    current_user = Depends(get_current_user)
):
    """Récupérer le détail d'un devoir avec tous ses fichiers"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Récupérer le devoir
        cursor.execute("""
            SELECT d.*, 
                   u.nom as parent_nom, u.prenom as parent_prenom,
                   e.nom as enfant_nom, e.prenom as enfant_prenom, e.age, e.classe
            FROM devoirs d
            JOIN users u ON d.parent_id = u.id
            JOIN enfants e ON d.enfant_id = e.id
            WHERE d.id = ?
        """, (devoir_id,))
        
        row = cursor.fetchone()
        if not row:
            raise HTTPException(404, "Devoir non trouvé")
        
        devoir = dict(row)
        
        # Vérifier les permissions
        if devoir["parent_id"] != current_user["id"]:
            raise HTTPException(403, "Vous n'avez pas accès à ce devoir")
        
        # Récupérer les fichiers
        cursor.execute("""
            SELECT * FROM devoir_fichiers 
            WHERE devoir_id = ?
            ORDER BY uploaded_at
        """, (devoir_id,))
        
        fichiers_rows = cursor.fetchall()
        devoir["fichiers"] = [dict(f) for f in fichiers_rows]
        
        conn.close()
        
        return {
            "devoir": devoir,
            "nb_fichiers": len(devoir["fichiers"])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération détail devoir: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

# ============ ENDPOINTS POUR LES ENFANTS ============

@app.post("/parents/{parent_id}/enfants")
async def ajouter_enfant(
    parent_id: int,
    enfant_data: EnfantCreate,  # Utiliser Pydantic model au lieu de Form
    current_user = Depends(get_current_user)
):
    """Ajouter un enfant pour un parent"""
    try:
        if current_user["id"] != parent_id:
            raise HTTPException(403, "Accès non autorisé")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Insérer l'enfant
        cursor.execute("""
            INSERT INTO enfants 
            (parent_id, nom, prenom, age, classe, niveau, ecole)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            parent_id, 
            enfant_data.nom, 
            enfant_data.prenom, 
            enfant_data.age, 
            enfant_data.classe, 
            enfant_data.niveau, 
            enfant_data.ecole
        ))
        
        enfant_id = cursor.lastrowid
        conn.commit()
        
        conn.close()
        
        return {
            "success": True,
            "message": "Enfant ajouté avec succès",
            "enfant_id": enfant_id,
            "enfant": {
                "id": enfant_id,
                "nom": enfant_data.nom,
                "prenom": enfant_data.prenom,
                "age": enfant_data.age,
                "classe": enfant_data.classe,
                "niveau": enfant_data.niveau,
                "ecole": enfant_data.ecole
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur ajout enfant: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/parents/{parent_id}/enfants")
async def get_enfants_parent(
    parent_id: int,
    current_user = Depends(get_current_user)
):
    """Récupérer tous les enfants d'un parent"""
    try:
        if current_user["id"] != parent_id:
            raise HTTPException(403, "Accès non autorisé")
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM enfants 
            WHERE parent_id = ?
            ORDER BY prenom
        """, (parent_id,))
        
        rows = cursor.fetchall()
        enfants = [dict(row) for row in rows]
        
        conn.close()
        
        return {
            "parent_id": parent_id,
            "enfants": enfants,
            "total": len(enfants)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération enfants: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

# ============ ENDPOINTS POUR CORRECTIONS ============

@app.post("/corrections/envoyer")
async def envoyer_correction(
    correction_data: str = Form(...),  # Données JSON en string
    fichiers: List[UploadFile] = File(None),
    current_user = Depends(get_current_user)
):
    """Envoyer une correction pour un devoir avec fichiers (version complète)"""
    try:
        # Vérifier que l'utilisateur est tuteur
        if current_user["role"] not in ["tuteur", "professeur"]:
            raise HTTPException(403, "Seuls les tuteurs peuvent envoyer des corrections")
        
        # Parser les données JSON
        try:
            data = json.loads(correction_data)
        except json.JSONDecodeError as e:
            raise HTTPException(400, f"Données JSON invalides: {str(e)}")
        
        # Champs obligatoires
        required_fields = ["devoir_id", "note", "commentaires"]
        for field in required_fields:
            if field not in data:
                raise HTTPException(400, f"Champ manquant: {field}")
        
        devoir_id = data["devoir_id"]
        tuteur_id = current_user["id"]
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que le devoir est assigné à ce tuteur
        cursor.execute("""
            SELECT da.id, d.titre 
            FROM devoir_assignations da
            JOIN devoirs d ON da.devoir_id = d.id
            WHERE da.devoir_id = ? 
            AND da.tuteur_id = ? 
            AND da.statut IN ('assigné', 'en_cours')
        """, (devoir_id, tuteur_id))
        
        assignation = cursor.fetchone()
        if not assignation:
            raise HTTPException(403, f"Ce devoir n'est pas assigné à vous ou est déjà corrigé")
        
        # Vérifier la note
        note = float(data.get("note", 0))
        if note < 0 or note > 20:
            raise HTTPException(400, "La note doit être entre 0 et 20")
        
        # Insérer la correction avec tous les champs
        cursor.execute("""
            INSERT INTO corrections (
                devoir_id, tuteur_id, note, commentaires, remarques,
                recommandations, temps_passe, difficulte, status_correction, date_correction,
                type_correction, format_explication, niveau_detail, methode_resolution,
                points_cles, erreurs_communes, conseils_pratiques, ressources_complementaires,
                temps_estime_eleve
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            devoir_id,
            tuteur_id,
            note,
            data.get("commentaires", ""),
            data.get("remarques", ""),
            data.get("recommandations", ""),
            data.get("temps_passe"),
            data.get("difficulte", "moyenne"),
            data.get("status_correction", "corrigé"),
            data.get("date_correction", datetime.now().isoformat()),
            data.get("type_correction", "correction_detaille"),
            data.get("format_explication", "textuel"),
            data.get("niveau_detail", "intermediaire"),
            data.get("methode_resolution", "standard"),
            data.get("points_cles", ""),
            data.get("erreurs_communes", ""),
            data.get("conseils_pratiques", ""),
            data.get("ressources_complementaires", ""),
            data.get("temps_estime_eleve")
        ))
        
        correction_id = cursor.lastrowid
        
        # Initialiser saved_files avant le bloc conditionnel
        saved_files = []
        
        # Sauvegarder les fichiers uploadés
        if fichiers:
            for fichier in fichiers:
                if fichier and fichier.filename:
                    try:
                        # Créer le dossier uploads/corrections s'il n'existe pas
                        upload_subdir = os.path.join(UPLOAD_DIR, "corrections")
                        os.makedirs(upload_subdir, exist_ok=True)
                        
                        # Générer un nom de fichier sécurisé
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        file_ext = os.path.splitext(fichier.filename)[1]
                        safe_filename = f"correction_{correction_id}_{timestamp}_{fichier.filename}"
                        file_path = os.path.join(upload_subdir, safe_filename)
                        
                        # Sauvegarder le fichier
                        content = await fichier.read()
                        with open(file_path, "wb") as buffer:
                            buffer.write(content)
                        
                        # Déterminer la catégorie du fichier
                        categorie = "correction"  # Par défaut
                        content_type = fichier.content_type or "application/octet-stream"
                        
                        # Enregistrer dans la base
                        cursor.execute("""
                            INSERT INTO correction_fichiers 
                            (correction_id, nom_fichier, chemin_fichier, type_fichier, taille, categorie)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (
                            correction_id,
                            fichier.filename,
                            file_path,
                            content_type,
                            len(content),
                            categorie
                        ))
                        
                        saved_files.append({
                            "nom_original": fichier.filename,
                            "chemin": file_path,
                            "type": content_type,
                            "taille": len(content),
                            "categorie": categorie
                        })
                        
                    except Exception as e:
                        logger.warning(f"⚠️ Erreur sauvegarde fichier {fichier.filename}: {str(e)}")
                        # Continuer même si un fichier échoue
        
        # Mettre à jour le devoir
        cursor.execute("""
            UPDATE devoirs 
            SET statut = 'corrigé',
                note = ?,
                notes_tuteur = ?,
                date_correction = ?,
                tuteur_id = ?
            WHERE id = ?
        """, (
            note,
            data.get("commentaires", ""),
            data.get("date_correction", datetime.now().isoformat()),
            tuteur_id,
            devoir_id
        ))
        
        # Mettre à jour l'assignation
        cursor.execute("""
            UPDATE devoir_assignations 
            SET statut = 'terminé'
            WHERE devoir_id = ?
        """, (devoir_id,))
        
        conn.commit()
        
        # Récupérer la correction créée
        cursor.execute("""
            SELECT c.*, 
                   u.nom as tuteur_nom, u.prenom as tuteur_prenom,
                   d.titre as devoir_titre,
                   e.nom as enfant_nom, e.prenom as enfant_prenom
            FROM corrections c
            JOIN users u ON c.tuteur_id = u.id
            JOIN devoirs d ON c.devoir_id = d.id
            JOIN enfants e ON d.enfant_id = e.id
            WHERE c.id = ?
        """, (correction_id,))
        
        row = cursor.fetchone()
        correction = dict(row) if row else {}
        
        # Récupérer les fichiers associés
        cursor.execute("""
            SELECT * FROM correction_fichiers 
            WHERE correction_id = ?
            ORDER BY uploaded_at
        """, (correction_id,))
        
        fichiers_rows = cursor.fetchall()
        correction["fichiers"] = [dict(f) for f in fichiers_rows]
        
        conn.close()
        
        return {
            "success": True,
            "message": "Correction envoyée avec succès",
            "correction_id": correction_id,
            "correction": correction,
            "fichiers_sauvegardes": len(saved_files)  # Maintenant la variable est toujours définie
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur envoi correction: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")
# ============ ENDPOINTS ADMIN ============

@app.get("/admin/corrections/pending")
async def get_corrections_pending(
    current_user = Depends(get_current_user)
):
    """Récupérer les corrections en attente de validation (admin seulement)"""
    try:
        if current_user["role"] != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                c.*,
                d.titre as devoir_titre,
                u_tuteur.nom as tuteur_nom, u_tuteur.prenom as tuteur_prenom,
                u_parent.nom as parent_nom, u_parent.prenom as parent_prenom,
                e.nom as enfant_nom, e.prenom as enfant_prenom
            FROM corrections c
            JOIN devoirs d ON c.devoir_id = d.id
            JOIN users u_tuteur ON c.tuteur_id = u_tuteur.id
            JOIN users u_parent ON d.parent_id = u_parent.id
            JOIN enfants e ON d.enfant_id = e.id
            WHERE c.valide_par_admin = FALSE
            ORDER BY c.date_envoi DESC
        """)
        
        rows = cursor.fetchall()
        corrections = [dict(row) for row in rows]
        
        conn.close()
        
        return {
            "corrections": corrections,
            "total": len(corrections)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération corrections en attente: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

# ============ ENDPOINTS DE GESTION ============

@app.get("/test/insert")
async def test_insert():
    """Test: insertion manuelle"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        test_email = f"test_{datetime.now().strftime('%Y%m%d%H%M%S')}@example.com"
        
        cursor.execute("""
            INSERT INTO users (nom, prenom, email, password_hash, accept_terms, role)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("Test", "Auto", test_email, hash_password("test123"), True, "etudiant"))
        
        conn.commit()
        user_id = cursor.lastrowid
        
        return {
            "success": True,
            "message": "Test insertion SQLite réussie",
            "user_id": user_id,
            "email": test_email
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()

@app.get("/users")
async def list_users():
    """Liste tous les utilisateurs"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT id, nom, prenom, email, role, created_at 
            FROM users ORDER BY id DESC
        """)
        
        rows = cursor.fetchall()
        users = [dict(row) for row in rows]
        
        return {
            "users": users,
            "count": len(users)
        }
    finally:
        conn.close()

# ============ ENDPOINTS POUR TRAVAUX CORRIGÉS DES TUTEURS ============

@app.get("/tuteur/mes-corrections")
async def get_mes_corrections(
    current_user = Depends(get_current_user),
    statut: str = "all",
    matiere: str = "",
    date_debut: str = "",
    date_fin: str = "",
    page: int = 1,
    per_page: int = 20
):
    """Récupérer toutes les corrections envoyées par un tuteur"""
    try:
        # Vérifier que l'utilisateur est tuteur
        if current_user["role"] not in ["tuteur", "professeur"]:
            raise HTTPException(403, "Accès réservé aux tuteurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Requête principale
        base_query = """
            SELECT 
                c.id,
                c.devoir_id,
                c.note,
                c.commentaires,
                c.remarques,
                c.recommandations,
                c.temps_passe,
                c.difficulte,
                c.status_correction,
                c.date_correction,
                c.date_envoi,
                c.type_correction,
                c.format_explication,
                c.niveau_detail,
                c.methode_resolution,
                c.points_cles,
                c.erreurs_communes,
                c.conseils_pratiques,
                c.ressources_complementaires,
                c.temps_estime_eleve,
                c.valide_par_admin,
                
                -- Information du devoir
                d.titre as devoir_titre,
                d.description as devoir_description,
                d.matiere as devoir_matiere,
                d.niveau as devoir_niveau,
                d.date_remise,
                d.statut as devoir_statut,
                d.date_correction as devoir_date_correction,
                
                -- Information de l'enfant
                e.id as enfant_id,
                e.nom as enfant_nom,
                e.prenom as enfant_prenom,
                e.age as enfant_age,
                e.classe as enfant_classe,
                e.niveau as enfant_niveau,
                
                -- Information du parent
                p.id as parent_id,
                p.nom as parent_nom,
                p.prenom as parent_prenom,
                p.email as parent_email,
                
                -- Nombre de fichiers
                (SELECT COUNT(*) FROM correction_fichiers cf WHERE cf.correction_id = c.id) as nb_fichiers,
                
                -- Évaluation du parent (si disponible)
                (SELECT note FROM evaluations WHERE correction_id = c.id) as evaluation_note,
                (SELECT commentaire FROM evaluations WHERE correction_id = c.id) as evaluation_commentaire
                
            FROM corrections c
            JOIN devoirs d ON c.devoir_id = d.id
            JOIN enfants e ON d.enfant_id = e.id
            JOIN users p ON d.parent_id = p.id
            WHERE c.tuteur_id = ?
        """
        
        params = [current_user["id"]]
        
        # Filtres
        filters = []
        
        if statut != "all":
            filters.append("c.status_correction = ?")
            params.append(statut)
        
        if matiere:
            filters.append("d.matiere LIKE ?")
            params.append(f"%{matiere}%")
        
        if date_debut:
            filters.append("DATE(c.date_envoi) >= ?")
            params.append(date_debut)
        
        if date_fin:
            filters.append("DATE(c.date_envoi) <= ?")
            params.append(date_fin)
        
        if filters:
            base_query += " AND " + " AND ".join(filters)
        
        # Compter le total
        count_query = f"SELECT COUNT(*) FROM ({base_query})"
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Ajouter ORDER BY et pagination
        offset = (page - 1) * per_page
        base_query += " ORDER BY c.date_envoi DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        cursor.execute(base_query, params)
        rows = cursor.fetchall()
        
        # Formater les résultats
        corrections = []
        for row in rows:
            correction = dict(row)
            
            # Formater les dates
            if correction["date_envoi"]:
                correction["date_envoi_formatted"] = correction["date_envoi"].split()[0]
                correction["date_envoi_time"] = correction["date_envoi"].split()[1][:5]
            
            if correction["date_correction"]:
                correction["date_correction_formatted"] = correction["date_correction"]
            
            # Récupérer les fichiers
            cursor.execute("""
                SELECT * FROM correction_fichiers 
                WHERE correction_id = ?
                ORDER BY uploaded_at
            """, (correction["id"],))
            
            fichiers_rows = cursor.fetchall()
            correction["fichiers"] = [dict(f) for f in fichiers_rows]
            
            # Calculer des métriques
            correction["satisfaction"] = (
                "excellente" if correction.get("evaluation_note", 0) >= 4.5 else
                "bonne" if correction.get("evaluation_note", 0) >= 4 else
                "moyenne" if correction.get("evaluation_note", 0) >= 3 else
                "à améliorer"
            )
            
            # Couleur selon la note
            note = correction["note"]
            if note >= 16:
                correction["note_color"] = "#10B981"  # Vert
                correction["note_label"] = "Excellent"
            elif note >= 12:
                correction["note_color"] = "#F59E0B"  # Orange
                correction["note_label"] = "Bon"
            elif note >= 8:
                correction["note_color"] = "#F59E0B"  # Orange clair
                correction["note_label"] = "Moyen"
            else:
                correction["note_color"] = "#EF4444"  # Rouge
                correction["note_label"] = "À améliorer"
            
            corrections.append(correction)
        
        # Statistiques pour le tuteur
        cursor.execute("""
            SELECT 
                COUNT(*) as total_corrections,
                AVG(note) as note_moyenne,
                SUM(temps_passe) as temps_total,
                COUNT(DISTINCT d.matiere) as matieres_differentes,
                COUNT(DISTINCT d.parent_id) as parents_differents
            FROM corrections c
            JOIN devoirs d ON c.devoir_id = d.id
            WHERE c.tuteur_id = ?
        """, (current_user["id"],))
        
        stats_row = cursor.fetchone()
        stats = dict(stats_row) if stats_row else {}
        
        conn.close()
        
        return {
            "corrections": corrections,
            "stats": stats,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": (total + per_page - 1) // per_page
            },
            "filters": {
                "statut": statut,
                "matiere": matiere,
                "date_debut": date_debut,
                "date_fin": date_fin
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération corrections tuteur: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/tuteur/corrections/{correction_id}/detail")
async def get_correction_detail(
    correction_id: int,
    current_user = Depends(get_current_user)
):
    """Récupérer le détail complet d'une correction"""
    try:
        if current_user["role"] not in ["tuteur", "professeur"]:
            raise HTTPException(403, "Accès réservé aux tuteurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Récupérer la correction avec toutes les informations
        cursor.execute("""
            SELECT 
                c.*,
                d.titre as devoir_titre,
                d.description as devoir_description,
                d.matiere as devoir_matiere,
                d.niveau as devoir_niveau,
                d.date_remise,
                d.statut as devoir_statut,
                d.note as devoir_note,
                d.notes_tuteur as devoir_notes_tuteur,
                
                e.id as enfant_id,
                e.nom as enfant_nom,
                e.prenom as enfant_prenom,
                e.age as enfant_age,
                e.classe as enfant_classe,
                e.niveau as enfant_niveau,
                e.ecole as enfant_ecole,
                
                p.id as parent_id,
                p.nom as parent_nom,
                p.prenom as parent_prenom,
                p.email as parent_email,
                p.telephone as parent_telephone,
                
                t.nom as tuteur_nom,
                t.prenom as tuteur_prenom,
                t.email as tuteur_email,
                t.telephone as tuteur_telephone
                
            FROM corrections c
            JOIN devoirs d ON c.devoir_id = d.id
            JOIN enfants e ON d.enfant_id = e.id
            JOIN users p ON d.parent_id = p.id
            JOIN users t ON c.tuteur_id = t.id
            WHERE c.id = ? AND c.tuteur_id = ?
        """, (correction_id, current_user["id"]))
        
        row = cursor.fetchone()
        if not row:
            raise HTTPException(404, "Correction non trouvée ou accès non autorisé")
        
        correction = dict(row)
        
        # Récupérer les fichiers
        cursor.execute("""
            SELECT * FROM correction_fichiers 
            WHERE correction_id = ?
            ORDER BY uploaded_at
        """, (correction_id,))
        
        fichiers_rows = cursor.fetchall()
        correction["fichiers"] = [dict(f) for f in fichiers_rows]
        
        # Récupérer les évaluations
        cursor.execute("""
            SELECT * FROM evaluations 
            WHERE correction_id = ?
            ORDER BY date_evaluation DESC
        """, (correction_id,))
        
        evaluations_rows = cursor.fetchall()
        correction["evaluations"] = [dict(e) for e in evaluations_rows]
        
        # Récupérer les fichiers du devoir original
        cursor.execute("""
            SELECT * FROM devoir_fichiers 
            WHERE devoir_id = ?
            ORDER BY uploaded_at
        """, (correction["devoir_id"],))
        
        devoir_fichiers_rows = cursor.fetchall()
        correction["devoir_fichiers"] = [dict(f) for f in devoir_fichiers_rows]
        
        conn.close()
        
        return {"correction": correction}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération détail correction: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/tuteur/corrections/stats")
async def get_corrections_stats(current_user = Depends(get_current_user)):
    """Récupérer les statistiques des corrections"""
    try:
        if current_user["role"] not in ["tuteur", "professeur"]:
            raise HTTPException(403, "Accès réservé aux tuteurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Statistiques générales
        cursor.execute("""
            SELECT 
                COUNT(*) as total_corrections,
                COUNT(DISTINCT devoir_id) as devoirs_corriges,
                AVG(note) as note_moyenne,
                SUM(temps_passe) as temps_total_heures,
                MIN(date_envoi) as premiere_correction,
                MAX(date_envoi) as derniere_correction
            FROM corrections 
            WHERE tuteur_id = ?
        """, (current_user["id"],))
        
        stats_general = dict(cursor.fetchone())
        
        # Statistiques par matière
        cursor.execute("""
            SELECT 
                d.matiere,
                COUNT(*) as nombre_corrections,
                AVG(c.note) as note_moyenne,
                SUM(c.temps_passe) as temps_total
            FROM corrections c
            JOIN devoirs d ON c.devoir_id = d.id
            WHERE c.tuteur_id = ?
            GROUP BY d.matiere
            ORDER BY nombre_corrections DESC
        """, (current_user["id"],))
        
        stats_matiere = [dict(row) for row in cursor.fetchall()]
        
        # Statistiques par mois (derniers 6 mois)
        cursor.execute("""
            SELECT 
                strftime('%Y-%m', date_envoi) as mois,
                COUNT(*) as nombre_corrections,
                AVG(note) as note_moyenne
            FROM corrections 
            WHERE tuteur_id = ?
                AND date_envoi >= date('now', '-6 months')
            GROUP BY strftime('%Y-%m', date_envoi)
            ORDER BY mois DESC
        """, (current_user["id"],))
        
        stats_mois = [dict(row) for row in cursor.fetchall()]
        
        # Répartition par statut
        cursor.execute("""
            SELECT 
                status_correction,
                COUNT(*) as nombre,
                AVG(note) as note_moyenne
            FROM corrections 
            WHERE tuteur_id = ?
            GROUP BY status_correction
        """, (current_user["id"],))
        
        stats_statut = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "general": stats_general,
            "par_matiere": stats_matiere,
            "par_mois": stats_mois,
            "par_statut": stats_statut
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération stats corrections: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.put("/parents/{parent_id}/enfants/{enfant_id}")
async def modifier_enfant(
    parent_id: int,
    enfant_id: int,
    nom: str = Form(None),
    prenom: str = Form(None),
    age: int = Form(None),
    classe: str = Form(None),
    niveau: str = Form(None),
    ecole: str = Form(None),
    current_user = Depends(get_current_user)
):
    """Modifier un enfant"""
    try:
        if current_user["id"] != parent_id:
            raise HTTPException(403, "Accès non autorisé")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que l'enfant appartient au parent
        cursor.execute("""
            SELECT * FROM enfants 
            WHERE id = ? AND parent_id = ?
        """, (enfant_id, parent_id))
        
        enfant = cursor.fetchone()
        if not enfant:
            raise HTTPException(404, "Enfant non trouvé")
        
        # Construire la requête de mise à jour dynamique
        updates = []
        values = []
        
        if nom is not None:
            updates.append("nom = ?")
            values.append(nom)
        if prenom is not None:
            updates.append("prenom = ?")
            values.append(prenom)
        if age is not None:
            updates.append("age = ?")
            values.append(age)
        if classe is not None:
            updates.append("classe = ?")
            values.append(classe)
        if niveau is not None:
            updates.append("niveau = ?")
            values.append(niveau)
        if ecole is not None:
            updates.append("ecole = ?")
            values.append(ecole)
        
        if updates:
            values.append(enfant_id)
            values.append(parent_id)
            
            sql = f"""
                UPDATE enfants 
                SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND parent_id = ?
            """
            
            cursor.execute(sql, values)
            conn.commit()
        
        # Récupérer l'enfant mis à jour
        cursor.execute("""
            SELECT * FROM enfants WHERE id = ?
        """, (enfant_id,))
        
        enfant_updated = cursor.fetchone()
        
        conn.close()
        
        return {
            "success": True,
            "message": "Enfant mis à jour avec succès",
            "enfant": dict(enfant_updated) if enfant_updated else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur modification enfant: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.delete("/parents/{parent_id}/enfants/{enfant_id}")
async def supprimer_enfant(
    parent_id: int,
    enfant_id: int,
    current_user = Depends(get_current_user)
):
    """Supprimer un enfant"""
    try:
        if current_user["id"] != parent_id:
            raise HTTPException(403, "Accès non autorisé")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que l'enfant appartient au parent
        cursor.execute("""
            SELECT id FROM enfants 
            WHERE id = ? AND parent_id = ?
        """, (enfant_id, parent_id))
        
        if not cursor.fetchone():
            raise HTTPException(404, "Enfant non trouvé")
        
        # Supprimer l'enfant
        cursor.execute("DELETE FROM enfants WHERE id = ?", (enfant_id,))
        conn.commit()
        
        conn.close()
        
        return {
            "success": True,
            "message": "Enfant supprimé avec succès"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur suppression enfant: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")
    
@app.get("/parents/{parent_id}/enfants/{enfant_id}")
async def get_enfant(
    parent_id: int,
    enfant_id: int,
    current_user = Depends(get_current_user)
):
    """Récupérer un enfant spécifique"""
    try:
        if current_user["id"] != parent_id:
            raise HTTPException(403, "Accès non autorisé")
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM enfants 
            WHERE id = ? AND parent_id = ?
        """, (enfant_id, parent_id))
        
        row = cursor.fetchone()
        if not row:
            raise HTTPException(404, "Enfant non trouvé")
        
        conn.close()
        
        return {
            "enfant": dict(row)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération enfant: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/users/{user_id}")
async def get_user(user_id: int):
    """Récupère un utilisateur par son ID"""
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT id, nom, prenom, email, telephone, role, profession, 
                   diplome, experience, etablissement, is_verified, 
                   verification_status, created_at
            FROM users WHERE id = ?
        """, (user_id,))
        
        row = cursor.fetchone()
        if not row:
            raise HTTPException(404, "Utilisateur non trouvé")
        
        return {"user": dict(row)}
    finally:
        conn.close()

@app.get("/admin/tables")
async def get_all_tables(current_user = Depends(get_current_user)):
    """Récupère toutes les tables de la base de données"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Récupérer la liste des tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [row[0] for row in cursor.fetchall()]
        
        table_data = {}
        for table in tables:
            # Récupérer les colonnes
            cursor.execute(f"PRAGMA table_info({table})")
            columns = cursor.fetchall()
            
            # Récupérer quelques enregistrements
            try:
                cursor.execute(f"SELECT * FROM {table} ORDER BY ROWID DESC LIMIT 50")
                rows = cursor.fetchall()
                records = [dict(row) for row in rows]
                total = len(records)
            except Exception as e:
                print(f"Erreur table {table}: {str(e)}")
                records = []
                total = 0
            
            table_data[table] = {
                "name": table,
                "columns": [{"name": col[1], "type": col[2]} for col in columns],
                "records": records,
                "total_records": total
            }
        
        conn.close()
        
        return {"tables": tables, "table_data": table_data}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération tables: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/table/{table_name}")
async def get_table_data(
    table_name: str,
    search: str = "",
    limit: int = 50,
    offset: int = 0,
    sort_by: str = "id",
    sort_order: str = "DESC",
    current_user = Depends(get_current_user)
):
    """Récupère les données d'une table spécifique"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        # Liste des tables autorisées
        allowed_tables = [
            "users", "user_documents", "enfants", "devoirs", "devoir_fichiers",
            "travaux_corriges", "travail_corrige_fichiers", "devoir_assignations",
            "corrections", "correction_fichiers"
        ]
        
        if table_name not in allowed_tables:
            raise HTTPException(400, f"Table non autorisée: {table_name}")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Récupérer les colonnes
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns_data = cursor.fetchall()
        columns = [{"name": col[1], "type": col[2], "nullable": not col[3]} for col in columns_data]
        
        # Construire la requête SQL
        base_query = f"SELECT * FROM {table_name}"
        count_query = f"SELECT COUNT(*) FROM {table_name}"
        where_clauses = []
        params = []
        
        # Ajouter la recherche si spécifiée
        if search:
            searchable_columns = [col[1] for col in columns_data 
                                 if col[1] not in ["id", "password_hash", "created_at", "updated_at"]]
            search_clauses = []
            for col in searchable_columns:
                search_clauses.append(f"{col} LIKE ?")
                params.append(f"%{search}%")
            
            if search_clauses:
                where_clauses.append(f"({' OR '.join(search_clauses)})")
        
        # Ajouter les clauses WHERE
        if where_clauses:
            where_sql = " WHERE " + " AND ".join(where_clauses)
            base_query += where_sql
            count_query += where_sql
        
        # Compter le nombre total d'enregistrements
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Ajouter le tri et la pagination
        order_sql = f" ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?"
        base_query += order_sql
        params.extend([limit, offset])
        
        # Exécuter la requête principale
        cursor.execute(base_query, params)
        rows = cursor.fetchall()
        
        # Formater les résultats
        records = []
        for row in rows:
            record = {}
            for idx, col in enumerate(columns_data):
                value = row[idx]
                
                # Formater les dates
                if isinstance(value, str) and 'TIMESTAMP' in columns_data[idx][2].upper():
                    try:
                        record[col[1]] = value.split()[0] if value else None
                    except:
                        record[col[1]] = value
                # Masquer les mots de passe
                elif col[1] == "password_hash":
                    record[col[1]] = "********" if value else None
                # Formater les JSON/arrays
                elif isinstance(value, str) and (value.startswith('[') or value.startswith('{')):
                    try:
                        record[col[1]] = json.loads(value)
                    except:
                        record[col[1]] = value
                else:
                    record[col[1]] = value
            
            records.append(record)
        
        # Récupérer les clés étrangères
        cursor.execute(f"PRAGMA foreign_key_list({table_name})")
        foreign_keys = cursor.fetchall()
        
        conn.close()
        
        return {
            "table_name": table_name,
            "columns": columns,
            "records": records,
            "total": total,
            "page": offset // limit + 1,
            "total_pages": (total + limit - 1) // limit,
            "foreign_keys": foreign_keys
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération table {table_name}: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/travaux-corriges")
async def get_travaux_corriges_admin(
    search: str = "",
    matiere: str = "",
    niveau: str = "",
    statut: str = "publié",
    page: int = 1,
    per_page: int = 20,
    current_user = Depends(get_current_user)
):
    """Récupère les travaux corrigés pour l'admin"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        base_query = """
            SELECT 
                tc.id,
                tc.titre,
                tc.description,
                tc.matiere,
                tc.niveau,
                tc.type_travail,
                tc.date_travail,
                tc.date_correction,
                tc.note_maximale,
                tc.difficulte,
                tc.temps_estime,
                tc.competences,
                tc.points_forts,
                tc.points_amelioration,
                tc.commentaires_generaux,
                tc.statut,
                tc.created_at,
                
                -- Tuteur info
                u.id as tuteur_id,
                u.nom as tuteur_nom,
                u.prenom as tuteur_prenom,
                u.email as tuteur_email,
                
                -- Fichiers count
                (SELECT COUNT(*) FROM travail_corrige_fichiers tcf WHERE tcf.travail_id = tc.id) as nb_fichiers
                
            FROM travaux_corriges tc
            JOIN users u ON tc.tuteur_id = u.id
            WHERE 1=1
        """
        
        where_clauses = []
        params = []
        
        if search:
            where_clauses.append("""
                (tc.titre LIKE ? OR tc.description LIKE ? OR tc.matiere LIKE ? OR
                u.nom LIKE ? OR u.prenom LIKE ?)
            """)
            search_param = f"%{search}%"
            params.extend([search_param] * 5)
        
        if matiere:
            where_clauses.append("tc.matiere = ?")
            params.append(matiere)
        
        if niveau:
            where_clauses.append("tc.niveau = ?")
            params.append(niveau)
        
        if statut != "all":
            where_clauses.append("tc.statut = ?")
            params.append(statut)
        
        # Compter le total
        count_query = "SELECT COUNT(*) FROM corrections tc JOIN users u ON tc.tuteur_id = u.id"
        if where_clauses:
            count_query += " WHERE " + " AND ".join(where_clauses)
        
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Ajouter WHERE à la requête principale
        if where_clauses:
            base_query += " AND " + " AND ".join(where_clauses)
        
        # Ajouter ORDER BY et pagination
        offset = (page - 1) * per_page
        base_query += " ORDER BY tc.created_at DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        cursor.execute(base_query, params)
        rows = cursor.fetchall()
        
        # Formater les résultats
        travaux = []
        for row in rows:
            travail = dict(row)
            
            # Formater la date
            if travail["created_at"]:
                travail["created_at_formatted"] = travail["created_at"].split()[0]
            
            # Récupérer les fichiers
            cursor.execute("""
                SELECT * FROM travail_corrige_fichiers 
                WHERE travail_id = ?
                ORDER BY uploaded_at
            """, (travail["id"],))
            
            fichiers_rows = cursor.fetchall()
            travail["fichiers"] = [dict(f) for f in fichiers_rows]
            
            # Formater les compétences
            if travail["competences"]:
                try:
                    travail["competences_list"] = json.loads(travail["competences"])
                except:
                    travail["competences_list"] = travail["competences"].split(",")
            else:
                travail["competences_list"] = []
            
            travaux.append(travail)
        
        conn.close()
        
        return {
            "travaux": travaux,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération travaux corrigés: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")


from fastapi.responses import FileResponse

@app.get("/download")
async def download_file(
    path: str,
    current_user = Depends(get_current_user)
):
    """Télécharger un fichier"""
    try:
        # Sécurité : vérifier que le chemin est dans uploads
        if not path.startswith("uploads/"):
            raise HTTPException(403, "Accès non autorisé")
        
        if not os.path.exists(path):
            raise HTTPException(404, "Fichier non trouvé")
        
        return FileResponse(
            path,
            media_type="application/octet-stream",
            filename=os.path.basename(path)
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur téléchargement fichier: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

# Supprimez l'ancienne route /tuteur/{tuteur_id} ou renommez-la
@app.get("/tuteur/mes-devoirs")
async def get_mes_devoirs(current_user = Depends(get_current_user)):
    """Récupérer les devoirs assignés au tuteur connecté"""
    try:
        if current_user.get("role") not in ["tuteur", "professeur"]:
            raise HTTPException(403, "Accès réservé aux tuteurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT 
                d.id,
                d.titre,
                d.description,
                d.matiere,
                d.date_remise,
                d.date_envoi,
                d.statut,
                d.priorite,
                d.niveau,
                d.type_devoir,
                
                p.id as parent_id,
                p.nom as parent_nom,
                p.prenom as parent_prenom,
                p.email as parent_email,
                
                e.id as enfant_id,
                e.nom as enfant_nom,
                e.prenom as enfant_prenom,
                e.age as enfant_age,
                e.classe as enfant_classe,
                e.niveau as enfant_niveau,
                e.ecole as enfant_ecole,
                
                da.id as assignation_id,
                da.date_assignation,
                da.date_limite,
                da.statut as statut_assignation,
                da.notes as notes_assignation
                
            FROM devoir_assignations da
            JOIN devoirs d ON da.devoir_id = d.id
            JOIN users p ON d.parent_id = p.id
            JOIN enfants e ON d.enfant_id = e.id
            WHERE da.tuteur_id = ?
            AND da.statut IN ('assigné', 'en_cours')
            ORDER BY 
                CASE 
                    WHEN da.date_limite < DATE('now') THEN 0
                    WHEN d.priorite = 'urgent' THEN 1
                    WHEN d.priorite = 'haute' THEN 2
                    ELSE 3
                END,
                da.date_limite ASC
        """, (current_user["id"],))
        
        rows = cursor.fetchall()
        devoirs = []
        
        for row in rows:
            devoir = dict(row)
            
            # Formater la date
            if devoir["date_remise"]:
                devoir["date_remise_formatted"] = devoir["date_remise"]
                try:
                    deadline = datetime.strptime(devoir["date_remise"], "%Y-%m-%d")
                    devoir["deadline_passed"] = deadline < datetime.now()
                except:
                    devoir["deadline_passed"] = False
            
            # Récupérer les fichiers
            cursor.execute("""
                SELECT id, nom_fichier, chemin_fichier, type_fichier, taille
                FROM devoir_fichiers 
                WHERE devoir_id = ?
                ORDER BY uploaded_at
            """, (devoir["id"],))
            
            devoir["fichiers"] = [dict(f) for f in cursor.fetchall()]
            
            devoirs.append(devoir)
        
        conn.close()
        
        return devoirs  # Retourne directement le tableau
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération devoirs tuteur: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/parents/{parent_id}/travaux")
async def get_travaux_parent(
    parent_id: int,
    statut: str = "all",  # all, envoyé, assigné, corrigé
    enfant_id: int = None,
    matiere: str = "",
    date_debut: str = "",
    date_fin: str = "",
    page: int = 1,
    per_page: int = 20,
    current_user = Depends(get_current_user)
):
    """Récupère tous les travaux envoyés par un parent avec leurs statuts"""
    try:
        # Vérifier que l'utilisateur est parent et accède à ses propres données
        if current_user["role"] != "parent" or current_user["id"] != parent_id:
            if current_user["role"] != "admin":
                raise HTTPException(403, "Accès non autorisé")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Requête principale avec toutes les informations
        base_query = """
            SELECT 
                d.id as devoir_id,
                d.titre,
                d.description,
                d.matiere,
                d.date_remise as deadline,
                d.date_envoi as date_envoi,
                d.statut,
                d.priorite,
                d.niveau,
                d.type_devoir,
                d.note,
                d.notes_tuteur,
                d.date_correction,
                
                -- Enfant info
                e.id as enfant_id,
                e.nom as enfant_nom,
                e.prenom as enfant_prenom,
                e.age,
                e.classe,
                e.ecole,
                
                -- Tuteur assigné (si applicable)
                t.id as tuteur_id,
                t.nom as tuteur_nom,
                t.prenom as tuteur_prenom,
                t.email as tuteur_email,
                
                -- Assignation info (si disponible)
                da.date_assignation,
                da.date_limite as date_limite_correction,
                da.statut as statut_assignation,
                da.notes as notes_assignation,
                
                -- Fichiers du devoir
                (SELECT COUNT(*) FROM devoir_fichiers df WHERE df.devoir_id = d.id) as nb_fichiers,
                
                -- Fichiers de correction (si disponibles)
                (SELECT COUNT(*) FROM correction_fichiers cf 
                 WHERE cf.correction_id IN (
                     SELECT id FROM corrections c WHERE c.devoir_id = d.id
                 )) as nb_fichiers_correction,
                
                -- Correction info (si disponible)
                c.note as note_correction,
                c.commentaires as commentaires_correction,
                c.date_correction as date_correction_reelle,
                c.status_correction
                
            FROM devoirs d
            JOIN enfants e ON d.enfant_id = e.id
            LEFT JOIN users t ON d.tuteur_id = t.id
            LEFT JOIN devoir_assignations da ON d.id = da.devoir_id
            LEFT JOIN corrections c ON d.id = c.devoir_id
            WHERE d.parent_id = ?
        """
        
        params = [parent_id]
        where_clauses = []
        
        # Filtre par statut
        if statut != "all":
            if statut == "corrigé":
                where_clauses.append("d.statut = 'corrigé'")
            elif statut == "assigné":
                where_clauses.append("d.statut = 'assigné'")
            elif statut == "envoyé":
                where_clauses.append("d.statut = 'envoyé'")
            elif statut == "en_attente":
                where_clauses.append("d.statut = 'en_attente'")
        
        # Filtre par enfant
        if enfant_id:
            where_clauses.append("d.enfant_id = ?")
            params.append(enfant_id)
        
        # Filtre par matière
        if matiere:
            where_clauses.append("d.matiere LIKE ?")
            params.append(f"%{matiere}%")
        
        # Filtre par date
        if date_debut:
            where_clauses.append("DATE(d.date_envoi) >= ?")
            params.append(date_debut)
        
        if date_fin:
            where_clauses.append("DATE(d.date_envoi) <= ?")
            params.append(date_fin)
        
        # Ajouter les clauses WHERE
        if where_clauses:
            base_query += " AND " + " AND ".join(where_clauses)
        
        # Compter le total
        count_query = f"SELECT COUNT(*) FROM ({base_query})"
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Ajouter ORDER BY et pagination
        offset = (page - 1) * per_page
        base_query += " ORDER BY d.date_envoi DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        cursor.execute(base_query, params)
        rows = cursor.fetchall()
        
        # Formater les résultats
        travaux = []
        for row in rows:
            travail = dict(row)
            
            # Formater les dates
            if travail["date_envoi"]:
                travail["date_envoi_formatted"] = travail["date_envoi"].split()[0]
                travail["date_envoi_time"] = travail["date_envoi"].split()[1][:5] if " " in travail["date_envoi"] else ""
            
            if travail["deadline"]:
                travail["deadline_formatted"] = travail["deadline"]
                # Calculer les jours restants
                try:
                    deadline_date = datetime.strptime(travail["deadline"], "%Y-%m-%d")
                    jours_restants = (deadline_date - datetime.now()).days
                    travail["jours_restants"] = jours_restants
                    travail["deadline_passed"] = jours_restants < 0
                except:
                    travail["jours_restants"] = None
                    travail["deadline_passed"] = False
            
            if travail["date_correction"]:
                travail["date_correction_formatted"] = travail["date_correction"]
            
            # Récupérer les fichiers du devoir
            cursor.execute("""
                SELECT * FROM devoir_fichiers 
                WHERE devoir_id = ?
                ORDER BY uploaded_at
            """, (travail["devoir_id"],))
            
            fichiers_rows = cursor.fetchall()
            travail["fichiers"] = [dict(f) for f in fichiers_rows]
            
            # Récupérer les fichiers de correction (si existants)
            cursor.execute("""
                SELECT cf.*, c.date_correction 
                FROM correction_fichiers cf
                JOIN corrections c ON cf.correction_id = c.id
                WHERE c.devoir_id = ?
                ORDER BY cf.uploaded_at
            """, (travail["devoir_id"],))
            
            correction_fichiers_rows = cursor.fetchall()
            travail["fichiers_correction"] = [dict(f) for f in correction_fichiers_rows]
            
            # Déterminer le statut avec couleur
            statut = travail["statut"]
            if statut == "corrigé":
                travail["statut_color"] = "#10B981"  # Vert
                travail["statut_label"] = "Corrigé"
                travail["statut_icon"] = "✅"
            elif statut == "assigné":
                travail["statut_color"] = "#F59E0B"  # Orange
                travail["statut_label"] = "En cours de correction"
                travail["statut_icon"] = "📝"
            elif statut == "en_attente":
                travail["statut_color"] = "#6B7280"  # Gris
                travail["statut_label"] = "En attente de tuteur"
                travail["statut_icon"] = "⏳"
            else:  # envoyé
                travail["statut_color"] = "#3B82F6"  # Bleu
                travail["statut_label"] = "Envoyé"
                travail["statut_icon"] = "📤"
            
            # Priorité avec couleur
            priorite = travail.get("priorite", "normal")
            if priorite == "urgent":
                travail["priorite_color"] = "#EF4444"
                travail["priorite_icon"] = "🚨"
            elif priorite == "haute":
                travail["priorite_color"] = "#F59E0B"
                travail["priorite_icon"] = "⚠️"
            else:
                travail["priorite_color"] = "#10B981"
                travail["priorite_icon"] = "📅"
            
            travaux.append(travail)
        
        # Statistiques pour le parent
        cursor.execute("""
            SELECT 
                COUNT(*) as total_travaux,
                COUNT(CASE WHEN statut = 'corrigé' THEN 1 END) as corrections,
                COUNT(CASE WHEN statut = 'assigné' THEN 1 END) as travaux_en_cours,
                COUNT(CASE WHEN statut = 'envoyé' THEN 1 END) as travaux_envoyes,
                AVG(note) as moyenne_notes
            FROM devoirs 
            WHERE parent_id = ?
        """, (parent_id,))
        
        stats_row = cursor.fetchone()
        stats = dict(stats_row) if stats_row else {}
        
        conn.close()
        
        return {
            "travaux": travaux,
            "stats": stats,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": (total + per_page - 1) // per_page
            },
            "filters": {
                "statut": statut,
                "enfant_id": enfant_id,
                "matiere": matiere,
                "date_debut": date_debut,
                "date_fin": date_fin
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération travaux parent: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/parents/{parent_id}/travaux/{devoir_id}/detail")
async def get_travail_detail_parent(
    parent_id: int,
    devoir_id: int,
    current_user = Depends(get_current_user)
):
    """Récupère le détail complet d'un travail avec correction"""
    try:
        # Vérifier les permissions
        if current_user["role"] != "parent" or current_user["id"] != parent_id:
            if current_user["role"] != "admin":
                raise HTTPException(403, "Accès non autorisé")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que le devoir appartient au parent
        cursor.execute("SELECT parent_id FROM devoirs WHERE id = ?", (devoir_id,))
        devoir_parent = cursor.fetchone()
        
        if not devoir_parent or devoir_parent["parent_id"] != parent_id:
            raise HTTPException(404, "Travail non trouvé ou accès non autorisé")
        
        # Récupérer toutes les informations du devoir
        cursor.execute("""
            SELECT 
                d.*,
                e.nom as enfant_nom,
                e.prenom as enfant_prenom,
                e.age,
                e.classe,
                e.niveau as enfant_niveau,
                e.ecole,
                
                t.id as tuteur_id,
                t.nom as tuteur_nom,
                t.prenom as tuteur_prenom,
                t.email as tuteur_email,
                t.telephone as tuteur_telephone,
                t.profession as tuteur_profession,
                t.experience as tuteur_experience,
                
                p.nom as parent_nom,
                p.prenom as parent_prenom,
                p.email as parent_email,
                
                -- Correction info
                c.id as correction_id,
                c.note as note_correction,
                c.commentaires as commentaires_correction,
                c.remarques,
                c.recommandations,
                c.temps_passe,
                c.difficulte,
                c.status_correction,
                c.date_correction as date_correction_complete,
                c.type_correction,
                c.format_explication,
                c.niveau_detail,
                c.methode_resolution,
                c.points_cles,
                c.erreurs_communes,
                c.conseils_pratiques,
                c.ressources_complementaires,
                c.temps_estime_eleve
                
            FROM devoirs d
            JOIN enfants e ON d.enfant_id = e.id
            JOIN users p ON d.parent_id = p.id
            LEFT JOIN users t ON d.tuteur_id = t.id
            LEFT JOIN corrections c ON d.id = c.devoir_id
            WHERE d.id = ? AND d.parent_id = ?
        """, (devoir_id, parent_id))
        
        row = cursor.fetchone()
        if not row:
            raise HTTPException(404, "Travail non trouvé")
        
        travail = dict(row)
        
        # Récupérer les fichiers du devoir
        cursor.execute("""
            SELECT * FROM devoir_fichiers 
            WHERE devoir_id = ?
            ORDER BY uploaded_at
        """, (devoir_id,))
        
        fichiers_rows = cursor.fetchall()
        travail["fichiers"] = [dict(f) for f in fichiers_rows]
        
        # Récupérer les fichiers de correction
        cursor.execute("""
            SELECT cf.* 
            FROM correction_fichiers cf
            JOIN corrections c ON cf.correction_id = c.id
            WHERE c.devoir_id = ?
            ORDER BY cf.uploaded_at
        """, (devoir_id,))
        
        correction_fichiers_rows = cursor.fetchall()
        travail["fichiers_correction"] = [dict(f) for f in correction_fichiers_rows]
        
        # Récupérer les assignations
        cursor.execute("""
            SELECT * FROM devoir_assignations 
            WHERE devoir_id = ?
            ORDER BY date_assignation DESC
        """, (devoir_id,))
        
        assignations_rows = cursor.fetchall()
        travail["assignations"] = [dict(a) for a in assignations_rows]
        
        conn.close()
        
        return {
            "travail": travail,
            "nb_fichiers": len(travail["fichiers"]),
            "nb_fichiers_correction": len(travail["fichiers_correction"])
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération détail travail: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/parents/{parent_id}/travaux-corriges")
async def get_travaux_corriges_parent(
    parent_id: int,
    enfant_id: int = None,
    matiere: str = "",
    note_min: float = 0,
    note_max: float = 20,
    date_debut: str = "",
    date_fin: str = "",
    page: int = 1,
    per_page: int = 20,
    current_user = Depends(get_current_user)
):
    """Récupère tous les travaux corrigés pour un parent"""
    try:
        # Vérifier les permissions
        if current_user["role"] != "parent" or current_user["id"] != parent_id:
            if current_user["role"] != "admin":
                raise HTTPException(403, "Accès non autorisé")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Requête pour les travaux corrigés
        base_query = """
            SELECT 
                d.id as devoir_id,
                d.titre,
                d.description,
                d.matiere,
                d.date_remise,
                d.date_envoi,
                d.statut,
                d.niveau,
                d.type_devoir,
                
                -- Note et correction
                d.note,
                d.notes_tuteur,
                d.date_correction,
                
                -- Correction détaillée
                c.id as correction_id,
                c.commentaires as commentaires_correction,
                c.remarques,
                c.recommandations,
                c.temps_passe,
                c.difficulte,
                c.status_correction,
                c.type_correction,
                c.format_explication,
                c.niveau_detail,
                c.methode_resolution,
                c.points_cles,
                c.erreurs_communes,
                c.conseils_pratiques,
                c.ressources_complementaires,
                c.temps_estime_eleve,
                
                -- Enfant info
                e.id as enfant_id,
                e.nom as enfant_nom,
                e.prenom as enfant_prenom,
                e.classe,
                e.age,
                
                -- Tuteur info
                t.id as tuteur_id,
                t.nom as tuteur_nom,
                t.prenom as tuteur_prenom,
                t.email as tuteur_email,
                t.profession as tuteur_profession,
                
                -- Fichiers
                (SELECT COUNT(*) FROM devoir_fichiers df WHERE df.devoir_id = d.id) as nb_fichiers,
                (SELECT COUNT(*) FROM correction_fichiers cf 
                 WHERE cf.correction_id = c.id) as nb_fichiers_correction
                
            FROM devoirs d
            JOIN enfants e ON d.enfant_id = e.id
            LEFT JOIN corrections c ON d.id = c.devoir_id
            LEFT JOIN users t ON d.tuteur_id = t.id
            WHERE d.parent_id = ?
            AND d.statut = 'corrigé'
            AND d.note IS NOT NULL
        """
        
        params = [parent_id]
        where_clauses = []
        
        # Filtres
        if enfant_id:
            where_clauses.append("d.enfant_id = ?")
            params.append(enfant_id)
        
        if matiere:
            where_clauses.append("d.matiere LIKE ?")
            params.append(f"%{matiere}%")
        
        if note_min > 0:
            where_clauses.append("d.note >= ?")
            params.append(note_min)
        
        if note_max < 20:
            where_clauses.append("d.note <= ?")
            params.append(note_max)
        
        if date_debut:
            where_clauses.append("DATE(d.date_correction) >= ?")
            params.append(date_debut)
        
        if date_fin:
            where_clauses.append("DATE(d.date_correction) <= ?")
            params.append(date_fin)
        
        # Ajouter les clauses WHERE
        if where_clauses:
            base_query += " AND " + " AND ".join(where_clauses)
        
        # Compter le total
        count_query = f"SELECT COUNT(*) FROM ({base_query})"
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Ajouter ORDER BY et pagination
        offset = (page - 1) * per_page
        base_query += " ORDER BY d.date_correction DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        cursor.execute(base_query, params)
        rows = cursor.fetchall()
        
        # Formater les résultats
        travaux_corriges = []
        for row in rows:
            travail = dict(row)
            
            # Formater les dates
            if travail["date_correction"]:
                travail["date_correction_formatted"] = travail["date_correction"].split()[0] if " " in str(travail["date_correction"]) else travail["date_correction"]
            
            if travail["date_envoi"]:
                travail["date_envoi_formatted"] = travail["date_envoi"].split()[0] if " " in str(travail["date_envoi"]) else travail["date_envoi"]
            
            # Couleur de la note
            note = float(travail["note"] or 0)
            if note >= 16:
                travail["note_color"] = "#10B981"  # Vert
                travail["note_label"] = "Excellent"
            elif note >= 12:
                travail["note_color"] = "#F59E0B"  # Orange
                travail["note_label"] = "Bon"
            elif note >= 8:
                travail["note_color"] = "#F59E0B"  # Orange clair
                travail["note_label"] = "Moyen"
            else:
                travail["note_color"] = "#EF4444"  # Rouge
                travail["note_label"] = "À améliorer"
            
            # Récupérer les fichiers
            cursor.execute("SELECT * FROM devoir_fichiers WHERE devoir_id = ?", (travail["devoir_id"],))
            travail["fichiers"] = [dict(f) for f in cursor.fetchall()]
            
            # Récupérer les fichiers de correction
            if travail["correction_id"]:
                cursor.execute("SELECT * FROM correction_fichiers WHERE correction_id = ?", (travail["correction_id"],))
                travail["fichiers_correction"] = [dict(f) for f in cursor.fetchall()]
            else:
                travail["fichiers_correction"] = []
            
            travaux_corriges.append(travail)
        
        # Statistiques des notes
        cursor.execute("""
            SELECT 
                COUNT(*) as total_corriges,
                AVG(note) as moyenne_generale,
                MIN(note) as note_minimale,
                MAX(note) as note_maximale,
                COUNT(CASE WHEN note >= 16 THEN 1 END) as excellent,
                COUNT(CASE WHEN note >= 12 AND note < 16 THEN 1 END) as bon,
                COUNT(CASE WHEN note >= 8 AND note < 12 THEN 1 END) as moyen,
                COUNT(CASE WHEN note < 8 THEN 1 END) as a_ameliorer
            FROM devoirs 
            WHERE parent_id = ? AND statut = 'corrigé' AND note IS NOT NULL
        """, (parent_id,))
        
        stats = dict(cursor.fetchone())
        
        # Répartition par matière
        cursor.execute("""
            SELECT 
                matiere,
                COUNT(*) as nombre,
                AVG(note) as moyenne
            FROM devoirs 
            WHERE parent_id = ? AND statut = 'corrigé' AND note IS NOT NULL
            GROUP BY matiere
            ORDER BY nombre DESC
        """, (parent_id,))
        
        stats_matiere = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "travaux_corriges": travaux_corriges,
            "stats": stats,
            "stats_matiere": stats_matiere,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "total_pages": (total + per_page - 1) // per_page
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération travaux corrigés: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")


@app.delete("/admin/table/{table_name}/{record_id}")
async def delete_table_record(
    table_name: str,
    record_id: int,
    current_user = Depends(get_current_user)
):
    """Supprime un enregistrement d'une table"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que la table existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        if not cursor.fetchone():
            raise HTTPException(404, f"Table {table_name} non trouvée")
        
        # Vérifier que l'enregistrement existe
        cursor.execute(f"SELECT * FROM {table_name} WHERE id = ?", (record_id,))
        if not cursor.fetchone():
            raise HTTPException(404, f"Enregistrement {record_id} non trouvé dans {table_name}")
        
        # Supprimer l'enregistrement
        cursor.execute(f"DELETE FROM {table_name} WHERE id = ?", (record_id,))
        conn.commit()
        
        conn.close()
        
        return {"success": True, "message": f"Enregistrement {record_id} supprimé de {table_name}"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur suppression {table_name}/{record_id}: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.put("/admin/table/{table_name}/{record_id}")
async def update_table_record(
    table_name: str,
    record_id: int,
    updates: dict,
    current_user = Depends(get_current_user)
):
    """Met à jour un enregistrement d'une table"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que la table existe
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
        if not cursor.fetchone():
            raise HTTPException(404, f"Table {table_name} non trouvée")
        
        # Vérifier que l'enregistrement existe
        cursor.execute(f"SELECT * FROM {table_name} WHERE id = ?", (record_id,))
        if not cursor.fetchone():
            raise HTTPException(404, f"Enregistrement {record_id} non trouvé dans {table_name}")
        
        # Récupérer les colonnes
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = [col[1] for col in cursor.fetchall()]
        
        # Filtrer les mises à jour pour ne garder que les colonnes existantes
        valid_updates = {}
        for key, value in updates.items():
            if key in columns and key != "id":
                valid_updates[key] = value
        
        if not valid_updates:
            raise HTTPException(400, "Aucune mise à jour valide fournie")
        
        # Construire la requête de mise à jour
        set_clauses = [f"{key} = ?" for key in valid_updates.keys()]
        values = list(valid_updates.values())
        values.append(record_id)
        
        sql = f"UPDATE {table_name} SET {', '.join(set_clauses)} WHERE id = ?"
        cursor.execute(sql, values)
        conn.commit()
        
        # Récupérer l'enregistrement mis à jour
        cursor.execute(f"SELECT * FROM {table_name} WHERE id = ?", (record_id,))
        row = cursor.fetchone()
        updated_record = dict(row) if row else None
        
        conn.close()
        
        return {
            "success": True,
            "message": f"Enregistrement {record_id} mis à jour dans {table_name}",
            "record": updated_record
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur mise à jour {table_name}/{record_id}: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/devoirs-details")
async def get_devoirs_detailed(
    search: str = "",
    status_filter: str = "all",
    date_from: str = "",
    date_to: str = "",
    page: int = 1,
    per_page: int = 20,
    current_user = Depends(get_current_user)
):
    """Récupère les devoirs avec toutes les informations détaillées"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Requête principale avec JOINs
        base_query = """
            SELECT 
                d.id,
                d.titre,
                d.description,
                d.matiere,
                d.date_remise,
                d.date_envoi,
                d.statut,
                d.priorite,
                d.type_devoir,
                d.niveau,
                d.note,
                d.notes_tuteur,
                d.date_correction,
                
                -- Parent info
                p.id as parent_id,
                p.nom as parent_nom,
                p.prenom as parent_prenom,
                p.email as parent_email,
                p.telephone as parent_telephone,
                
                -- Enfant info
                e.id as enfant_id,
                e.nom as enfant_nom,
                e.prenom as enfant_prenom,
                e.age as enfant_age,
                e.classe as enfant_classe,
                e.niveau as enfant_niveau,
                e.ecole as enfant_ecole,
                
                -- Tuteur affecté (si existe)
                t.id as tuteur_id,
                t.nom as tuteur_nom,
                t.prenom as tuteur_prenom,
                t.email as tuteur_email,
                
                -- Assignation info
                da.date_assignation,
                da.date_limite,
                da.statut as assignation_statut,
                
                -- Fichiers
                (SELECT COUNT(*) FROM devoir_fichiers df WHERE df.devoir_id = d.id) as nb_fichiers
                
            FROM devoirs d
            LEFT JOIN users p ON d.parent_id = p.id
            LEFT JOIN enfants e ON d.enfant_id = e.id
            LEFT JOIN users t ON d.tuteur_id = t.id
            LEFT JOIN devoir_assignations da ON d.id = da.devoir_id
        """
        
        # Construire les clauses WHERE
        where_clauses = []
        params = []
        
        if search:
            where_clauses.append("""
                (d.titre LIKE ? OR d.description LIKE ? OR d.matiere LIKE ? OR
                p.nom LIKE ? OR p.prenom LIKE ? OR p.email LIKE ? OR
                e.nom LIKE ? OR e.prenom LIKE ? OR t.nom LIKE ? OR t.prenom LIKE ?)
            """)
            search_param = f"%{search}%"
            params.extend([search_param] * 10)
        
        if status_filter != "all":
            where_clauses.append("d.statut = ?")
            params.append(status_filter)
        
        if date_from:
            where_clauses.append("DATE(d.date_envoi) >= ?")
            params.append(date_from)
        
        if date_to:
            where_clauses.append("DATE(d.date_envoi) <= ?")
            params.append(date_to)
        
        # Compter le total
        count_query = "SELECT COUNT(*) FROM devoirs d"
        if where_clauses:
            count_query += " WHERE " + " AND ".join(where_clauses)
        
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Ajouter WHERE à la requête principale
        if where_clauses:
            base_query += " WHERE " + " AND ".join(where_clauses)
        
        # Ajouter ORDER BY et pagination
        offset = (page - 1) * per_page
        base_query += " ORDER BY d.date_envoi DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        cursor.execute(base_query, params)
        rows = cursor.fetchall()
        
        # Formater les résultats
        devoirs = []
        for row in rows:
            devoir = dict(row)
            
            # Formater les dates
            if devoir["date_envoi"]:
                devoir["date_envoi_formatted"] = devoir["date_envoi"].split()[0] if devoir["date_envoi"] else ""
            
            if devoir["date_remise"]:
                devoir["date_remise_formatted"] = devoir["date_remise"]
            
            # Vérifier si deadline dépassée
            if devoir["date_remise"]:
                try:
                    deadline = datetime.strptime(devoir["date_remise"], "%Y-%m-%d")
                    devoir["deadline_passed"] = deadline < datetime.now()
                except:
                    devoir["deadline_passed"] = False
            
            # Récupérer les fichiers
            cursor.execute("""
                SELECT * FROM devoir_fichiers 
                WHERE devoir_id = ?
                ORDER BY uploaded_at
            """, (devoir["id"],))
            devoir["fichiers"] = [dict(f) for f in cursor.fetchall()]
            
            devoirs.append(devoir)
        
        conn.close()
        
        return {
            "devoirs": devoirs,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération devoirs détaillés: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.post("/admin/devoirs/{devoir_id}/assigner")
async def assigner_devoir_admin(
    devoir_id: int,
    tuteur_id: int = Form(...),
    date_limite: str = Form(...),
    priorite: str = Form("normal"),
    notes: str = Form(""),
    current_user = Depends(get_current_user)
):
    """Affecter un devoir à un tuteur (admin)"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que le devoir existe
        cursor.execute("SELECT * FROM devoirs WHERE id = ?", (devoir_id,))
        devoir = cursor.fetchone()
        if not devoir:
            raise HTTPException(404, "Devoir non trouvé")
        
        # Vérifier que le tuteur existe
        cursor.execute("SELECT * FROM users WHERE id = ? AND role IN ('tuteur', 'professeur')", (tuteur_id,))
        tuteur = cursor.fetchone()
        if not tuteur:
            raise HTTPException(404, "Tuteur non trouvé")
        
        # Créer l'assignation
        cursor.execute("""
            INSERT INTO devoir_assignations 
            (devoir_id, tuteur_id, assigne_par, date_limite, priorite, notes, statut)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (devoir_id, tuteur_id, current_user["id"], date_limite, priorite, notes, "assigné"))
        
        # Mettre à jour le devoir
        cursor.execute("""
            UPDATE devoirs 
            SET tuteur_id = ?, statut = 'assigné'
            WHERE id = ?
        """, (tuteur_id, devoir_id))
        
        conn.commit()
        assignation_id = cursor.lastrowid
        
        conn.close()
        
        return {
            "success": True,
            "message": f"Devoir {devoir_id} affecté au tuteur {tuteur_id}",
            "assignation_id": assignation_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur affectation devoir: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.post("/admin/devoirs/{devoir_id}/corriger")
async def corriger_devoir_admin(
    devoir_id: int,
    note: float = Form(...),
    commentaires: str = Form(...),
    remarques: str = Form(""),
    recommandations: str = Form(""),
    date_correction: str = Form(...),
    current_user = Depends(get_current_user)
):
    """Ajouter une correction à un devoir (admin)"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que le devoir existe et est assigné
        cursor.execute("""
            SELECT d.*, da.tuteur_id 
            FROM devoirs d
            LEFT JOIN devoir_assignations da ON d.id = da.devoir_id
            WHERE d.id = ?
        """, (devoir_id,))
        
        devoir = cursor.fetchone()
        if not devoir:
            raise HTTPException(404, "Devoir non trouvé")
        
        devoir = dict(devoir)
        
        # Créer la correction dans la table appropriée
        cursor.execute("""
            INSERT INTO corrections 
            (devoir_id, tuteur_id, note, commentaires, remarques, recommandations, 
             status_correction, date_correction)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            devoir_id,
            devoir.get("tuteur_id") or current_user["id"],
            note,
            commentaires,
            remarques,
            recommandations,
            "corrigé",
            date_correction
        ))
        
        # Mettre à jour le devoir
        cursor.execute("""
            UPDATE devoirs 
            SET note = ?, notes_tuteur = ?, statut = 'corrigé', date_correction = ?
            WHERE id = ?
        """, (note, commentaires, date_correction, devoir_id))
        
        # Mettre à jour l'assignation si elle existe
        cursor.execute("""
            UPDATE devoir_assignations 
            SET statut = 'terminé'
            WHERE devoir_id = ?
        """, (devoir_id,))
        
        conn.commit()
        correction_id = cursor.lastrowid
        
        conn.close()
        
        return {
            "success": True,
            "message": f"Devoir {devoir_id} corrigé avec la note {note}/20",
            "correction_id": correction_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur correction devoir: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/users/role/{role}")
async def get_users_by_role(
    role: str,
    search: str = "",
    status_filter: str = "all",
    page: int = 1,
    per_page: int = 20,
    current_user = Depends(get_current_user)
):
    """Récupère les utilisateurs par rôle (tuteur, parent, eleve)"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        # Rôles autorisés
        allowed_roles = ["tuteur", "parent", "eleve", "professeur"]
        if role not in allowed_roles:
            raise HTTPException(400, f"Rôle non autorisé: {role}. Rôles autorisés: {allowed_roles}")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Construire la requête
        base_query = """
            SELECT 
                id, nom, prenom, email, telephone, role,
                is_active, is_verified, verification_status,
                created_at, updated_at,
                profession, diplome, experience, etablissement,
                matieres, tarif_horaire
            FROM users 
            WHERE role = ?
        """
        
        count_query = "SELECT COUNT(*) FROM users WHERE role = ?"
        where_clauses = []
        params = [role]
        
        # Ajouter la recherche
        if search:
            where_clauses.append("""
                (nom LIKE ? OR prenom LIKE ? OR email LIKE ? OR 
                 telephone LIKE ? OR profession LIKE ? OR matieres LIKE ?)
            """)
            search_param = f"%{search}%"
            params.extend([search_param] * 6)
        
        # Ajouter le filtre de statut
        if status_filter != "all":
            if status_filter == "active":
                where_clauses.append("is_active = TRUE")
            elif status_filter == "inactive":
                where_clauses.append("is_active = FALSE")
            elif status_filter == "verified":
                where_clauses.append("is_verified = TRUE")
            elif status_filter == "pending":
                where_clauses.append("verification_status = 'pending'")
            elif status_filter == "approved":
                where_clauses.append("verification_status = 'approved'")
            elif status_filter == "rejected":
                where_clauses.append("verification_status = 'rejected'")
        
        # Ajouter les clauses WHERE
        if where_clauses:
            where_sql = " AND " + " AND ".join(where_clauses)
            base_query += where_sql
            count_query += where_sql
        
        # Compter le total
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        
        # Ajouter ORDER BY et pagination
        offset = (page - 1) * per_page
        base_query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([per_page, offset])
        
        cursor.execute(base_query, params)
        rows = cursor.fetchall()
        
        # Formater les résultats
        users = []
        for row in rows:
            user = dict(row)
            
            # Formater les dates
            if user["created_at"]:
                user["created_at_formatted"] = user["created_at"].split()[0]
            
            if user["updated_at"]:
                user["updated_at_formatted"] = user["updated_at"].split()[0]
            
            # Formater les matières (JSON)
            if user["matieres"] and user["matieres"].startswith('['):
                try:
                    user["matieres_list"] = json.loads(user["matieres"])
                except:
                    user["matieres_list"] = []
            else:
                user["matieres_list"] = []
            
            # Calculer le statut
            if not user["is_active"]:
                user["status"] = "inactive"
            elif user["verification_status"] == "pending":
                user["status"] = "pending"
            elif user["verification_status"] == "rejected":
                user["status"] = "rejected"
            elif user["is_verified"]:
                user["status"] = "verified"
            else:
                user["status"] = "active"
            
            users.append(user)
        
        conn.close()
        
        return {
            "role": role,
            "users": users,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération utilisateurs par rôle {role}: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/tuteurs/disponibles")
async def get_tuteurs_disponibles(
    matiere: str = "",
    min_experience: int = 0,
    max_tarif: int = 100000,
    current_user = Depends(get_current_user)
):
    """Récupère les tuteurs disponibles pour affectation"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Requête pour les tuteurs disponibles
        base_query = """
            SELECT 
                u.id, u.nom, u.prenom, u.email, u.telephone,
                u.profession, u.diplome, u.experience,
                u.matieres, u.tarif_horaire, u.is_verified,
                u.verification_status,
                -- Nombre de devoirs assignés en cours
                (SELECT COUNT(*) FROM devoir_assignations da 
                 WHERE da.tuteur_id = u.id AND da.statut IN ('assigné', 'en_cours')) as devoirs_en_cours,
                -- Taux d'occupation (simulé)
                CASE 
                    WHEN (SELECT COUNT(*) FROM devoir_assignations da 
                          WHERE da.tuteur_id = u.id) > 5 THEN 'élevé'
                    WHEN (SELECT COUNT(*) FROM devoir_assignations da 
                          WHERE da.tuteur_id = u.id) > 2 THEN 'moyen'
                    ELSE 'faible'
                END as taux_occupation
            FROM users u
            WHERE u.role IN ('tuteur', 'professeur')
            AND u.is_active = TRUE
            AND u.is_verified = TRUE
        """
        
        params = []
        
        # Filtre par matière
        if matiere:
            base_query += " AND (u.matieres LIKE ? OR u.profession LIKE ?)"
            params.extend([f"%{matiere}%", f"%{matiere}%"])
        
        # Filtre par expérience
        if min_experience > 0:
            # Extraire les années d'expérience du texte
            base_query += " AND (u.experience LIKE '%années%' OR u.experience LIKE '%ans%')"
        
        # Filtre par tarif
        base_query += " AND (u.tarif_horaire <= ? OR u.tarif_horaire IS NULL OR u.tarif_horaire = 0)"
        params.append(max_tarif)
        
        base_query += " ORDER BY u.is_verified DESC, u.created_at DESC"
        
        cursor.execute(base_query, params)
        rows = cursor.fetchall()
        
        # Formater les résultats
        tuteurs = []
        for row in rows:
            tuteur = dict(row)
            
            # Formater les matières
            if tuteur["matieres"] and tuteur["matieres"].startswith('['):
                try:
                    tuteur["matieres_list"] = json.loads(tuteur["matieres"])
                except:
                    tuteur["matieres_list"] = []
            else:
                tuteur["matieres_list"] = []
            
            # Calculer le taux d'occupation en pourcentage
            if tuteur["devoirs_en_cours"] >= 5:
                tuteur["occupation_percent"] = 80
            elif tuteur["devoirs_en_cours"] >= 3:
                tuteur["occupation_percent"] = 60
            elif tuteur["devoirs_en_cours"] >= 1:
                tuteur["occupation_percent"] = 30
            else:
                tuteur["occupation_percent"] = 10
            
            tuteur["disponible"] = tuteur["devoirs_en_cours"] < 5  # Max 5 devoirs en même temps
            
            tuteurs.append(tuteur)
        
        conn.close()
        
        return {
            "tuteurs": tuteurs,
            "total": len(tuteurs),
            "filters": {
                "matiere": matiere,
                "max_tarif": max_tarif
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération tuteurs disponibles: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.post("/admin/tuteurs/{tuteur_id}/verifier")
async def verifier_tuteur(
    tuteur_id: int,
    action: str = Form(...),  # "approve", "reject"
    notes: str = Form(""),
    current_user = Depends(get_current_user)
):
    """Approuve ou rejette la vérification d'un tuteur"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        if action not in ["approve", "reject"]:
            raise HTTPException(400, "Action invalide. Utilisez 'approve' ou 'reject'")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que l'utilisateur est un tuteur
        cursor.execute("""
            SELECT id, role, verification_status 
            FROM users 
            WHERE id = ? AND role IN ('tuteur', 'professeur')
        """, (tuteur_id,))
        
        tuteur = cursor.fetchone()
        if not tuteur:
            raise HTTPException(404, "Tuteur non trouvé")
        
        tuteur = dict(tuteur)
        
        # Mettre à jour le statut
        if action == "approve":
            new_status = "approved"
            is_verified = True
        else:
            new_status = "rejected"
            is_verified = False
        
        cursor.execute("""
            UPDATE users 
            SET verification_status = ?, 
                is_verified = ?,
                verification_notes = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (new_status, is_verified, notes, tuteur_id))
        
        conn.commit()
        
        # Récupérer le tuteur mis à jour
        cursor.execute("""
            SELECT id, nom, prenom, email, verification_status, is_verified
            FROM users WHERE id = ?
        """, (tuteur_id,))
        
        tuteur_updated = dict(cursor.fetchone())
        
        conn.close()
        
        return {
            "success": True,
            "message": f"Tuteur {'approuvé' if action == 'approve' else 'rejeté'} avec succès",
            "tuteur": tuteur_updated
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur vérification tuteur: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.post("/admin/tuteurs/{tuteur_id}/suspendre")
async def suspendre_tuteur(
    tuteur_id: int,
    raison: str = Form(""),
    duree_jours: int = Form(7),
    current_user = Depends(get_current_user)
):
    """Suspend un tuteur"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que l'utilisateur est un tuteur
        cursor.execute("""
            SELECT id, nom, prenom, email, is_active 
            FROM users 
            WHERE id = ? AND role IN ('tuteur', 'professeur')
        """, (tuteur_id,))
        
        tuteur = cursor.fetchone()
        if not tuteur:
            raise HTTPException(404, "Tuteur non trouvé")
        
        tuteur = dict(tuteur)
        
        # Suspendre le tuteur
        cursor.execute("""
            UPDATE users 
            SET is_active = FALSE,
                verification_notes = CONCAT(COALESCE(verification_notes, ''), 
                    '\n[', CURRENT_TIMESTAMP, '] Suspension: ', ?),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (raison, tuteur_id))
        
        conn.commit()
        
        conn.close()
        
        return {
            "success": True,
            "message": f"Tuteur {tuteur['prenom']} {tuteur['nom']} suspendu pour {duree_jours} jours",
            "raison": raison
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur suspension tuteur: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.post("/admin/tuteurs/{tuteur_id}/reactiver")
async def reactiver_tuteur(
    tuteur_id: int,
    current_user = Depends(get_current_user)
):
    """Réactive un tuteur suspendu"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que l'utilisateur est un tuteur
        cursor.execute("""
            SELECT id, nom, prenom, email, is_active 
            FROM users 
            WHERE id = ? AND role IN ('tuteur', 'professeur')
        """, (tuteur_id,))
        
        tuteur = cursor.fetchone()
        if not tuteur:
            raise HTTPException(404, "Tuteur non trouvé")
        
        tuteur = dict(tuteur)
        
        # Réactiver le tuteur
        cursor.execute("""
            UPDATE users 
            SET is_active = TRUE,
                verification_notes = CONCAT(COALESCE(verification_notes, ''), 
                    '\n[', CURRENT_TIMESTAMP, '] Réactivation'),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (tuteur_id,))
        
        conn.commit()
        
        conn.close()
        
        return {
            "success": True,
            "message": f"Tuteur {tuteur['prenom']} {tuteur['nom']} réactivé avec succès"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur réactivation tuteur: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/tuteurs/{tuteur_id}/stats")
async def get_tuteur_stats(
    tuteur_id: int,
    current_user = Depends(get_current_user)
):
    """Récupère les statistiques d'un tuteur"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Informations du tuteur
        cursor.execute("""
            SELECT 
                u.id, u.nom, u.prenom, u.email, u.telephone,
                u.profession, u.diplome, u.experience,
                u.matieres, u.tarif_horaire, u.is_verified,
                u.verification_status, u.created_at
            FROM users u
            WHERE u.id = ? AND u.role IN ('tuteur', 'professeur')
        """, (tuteur_id,))
        
        tuteur = cursor.fetchone()
        if not tuteur:
            raise HTTPException(404, "Tuteur non trouvé")
        
        tuteur = dict(tuteur)
        
        # Statistiques
        cursor.execute("""
            SELECT 
                COUNT(*) as total_devoirs,
                COUNT(CASE WHEN statut = 'corrigé' THEN 1 END) as devoirs_corriges,
                COUNT(CASE WHEN statut = 'assigné' THEN 1 END) as devoirs_en_cours,
                AVG(note) as note_moyenne
            FROM devoirs 
            WHERE tuteur_id = ?
        """, (tuteur_id,))
        
        stats = dict(cursor.fetchone())
        
        # Dernières affectations
        cursor.execute("""
            SELECT 
                d.id, d.titre, d.matiere, d.statut,
                d.date_envoi, d.date_correction, d.note,
                e.nom as enfant_nom, e.prenom as enfant_prenom,
                p.nom as parent_nom, p.prenom as parent_prenom
            FROM devoirs d
            JOIN enfants e ON d.enfant_id = e.id
            JOIN users p ON d.parent_id = p.id
            WHERE d.tuteur_id = ?
            ORDER BY d.date_envoi DESC
            LIMIT 10
        """, (tuteur_id,))
        
        derniers_devoirs = [dict(row) for row in cursor.fetchall()]
        
        # Documents
        cursor.execute("""
            SELECT * FROM user_documents 
            WHERE user_id = ?
            ORDER BY uploaded_at DESC
        """, (tuteur_id,))
        
        documents = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "tuteur": tuteur,
            "stats": stats,
            "derniers_devoirs": derniers_devoirs,
            "documents": documents
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération stats tuteur: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/parents/{parent_id}/stats")
async def get_parent_stats(
    parent_id: int,
    current_user = Depends(get_current_user)
):
    """Récupère les statistiques d'un parent"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Informations du parent
        cursor.execute("""
            SELECT 
                u.id, u.nom, u.prenom, u.email, u.telephone,
                u.created_at, u.is_active
            FROM users u
            WHERE u.id = ? AND u.role = 'parent'
        """, (parent_id,))
        
        parent = cursor.fetchone()
        if not parent:
            raise HTTPException(404, "Parent non trouvé")
        
        parent = dict(parent)
        
        # Enfants
        cursor.execute("""
            SELECT * FROM enfants 
            WHERE parent_id = ?
            ORDER BY created_at DESC
        """, (parent_id,))
        
        enfants = [dict(row) for row in cursor.fetchall()]
        
        # Statistiques des devoirs
        cursor.execute("""
            SELECT 
                COUNT(*) as total_devoirs,
                COUNT(CASE WHEN statut = 'corrigé' THEN 1 END) as devoirs_corriges,
                COUNT(CASE WHEN statut = 'envoyé' THEN 1 END) as devoirs_envoyes,
                COUNT(CASE WHEN statut = 'assigné' THEN 1 END) as devoirs_assignes,
                AVG(note) as note_moyenne
            FROM devoirs 
            WHERE parent_id = ?
        """, (parent_id,))
        
        stats = dict(cursor.fetchone())
        
        # Derniers devoirs
        cursor.execute("""
            SELECT 
                d.id, d.titre, d.matiere, d.statut,
                d.date_envoi, d.date_remise, d.note,
                e.nom as enfant_nom, e.prenom as enfant_prenom,
                t.nom as tuteur_nom, t.prenom as tuteur_prenom
            FROM devoirs d
            JOIN enfants e ON d.enfant_id = e.id
            LEFT JOIN users t ON d.tuteur_id = t.id
            WHERE d.parent_id = ?
            ORDER BY d.date_envoi DESC
            LIMIT 10
        """, (parent_id,))
        
        derniers_devoirs = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            "parent": parent,
            "enfants": enfants,
            "stats": stats,
            "derniers_devoirs": derniers_devoirs,
            "nb_enfants": len(enfants)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération stats parent: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.post("/admin/devoirs/{devoir_id}/assigner")
async def assigner_devoir(
    devoir_id: int,
    tuteur_id: int = Form(...),
    date_limite: str = Form(...),
    priorite: str = Form("normal"),
    notes: str = Form(""),
    current_user = Depends(get_current_user)
):
    """Affecte un devoir à un tuteur"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Vérifier que le devoir existe et est disponible
        cursor.execute("""
            SELECT id, titre, statut, parent_id, enfant_id
            FROM devoirs 
            WHERE id = ? AND (statut = 'en_attente' OR statut = 'envoyé')
        """, (devoir_id,))
        
        devoir = cursor.fetchone()
        if not devoir:
            raise HTTPException(400, "Devoir non trouvé ou déjà affecté")
        
        # Vérifier que le tuteur existe et est actif
        cursor.execute("""
            SELECT id, nom, prenom, email, is_active, is_verified
            FROM users 
            WHERE id = ? AND role IN ('tuteur', 'professeur')
        """, (tuteur_id,))
        
        tuteur = cursor.fetchone()
        if not tuteur:
            raise HTTPException(400, "Tuteur non trouvé")
        
        tuteur = dict(tuteur)
        
        if not tuteur["is_active"]:
            raise HTTPException(400, "Tuteur inactif")
        
        if not tuteur["is_verified"]:
            raise HTTPException(400, "Tuteur non vérifié")
        
        # Mettre à jour le devoir
        cursor.execute("""
            UPDATE devoirs 
            SET tuteur_id = ?, 
                date_limite_correction = ?,
                priorite = ?,
                statut = 'assigné',
                notes_admin = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (tuteur_id, date_limite, priorite, notes, devoir_id))
        
        # Créer une entrée dans les assignations
        cursor.execute("""
            INSERT INTO devoir_assignations (
                devoir_id, tuteur_id, parent_id, enfant_id,
                date_assignation, date_limite, priorite,
                statut, notes_admin
            ) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, 'assigné', ?)
        """, (
            devoir_id, tuteur_id, devoir["parent_id"], devoir["enfant_id"],
            date_limite, priorite, notes
        ))
        
        conn.commit()
        
        # Récupérer le devoir mis à jour
        cursor.execute("""
            SELECT d.*, 
                   u.nom as tuteur_nom, u.prenom as tuteur_prenom,
                   u.email as tuteur_email
            FROM devoirs d
            LEFT JOIN users u ON d.tuteur_id = u.id
            WHERE d.id = ?
        """, (devoir_id,))
        
        devoir_updated = dict(cursor.fetchone())
        
        conn.close()
        
        return {
            "success": True,
            "message": f"Devoir affecté au tuteur {tuteur['prenom']} {tuteur['nom']}",
            "devoir": devoir_updated
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur affectation devoir: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")


@app.get("/tuteur/mes-devoirs")
async def get_mes_devoirs(current_user = Depends(get_current_user)):
    """Récupérer les devoirs assignés au tuteur connecté"""
    try:
        # Vérifier que l'utilisateur est tuteur
        if current_user.get("role") not in ["tuteur", "professeur"]:
            raise HTTPException(403, "Accès réservé aux tuteurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # CORRECTION 1: Utiliser la table devoirs directement avec une sous-requête
        # pour vérifier l'assignation dans devoir_assignations
        cursor.execute("""
            SELECT 
                d.id as id,
                d.titre,
                d.description,
                d.matiere,
                d.date_remise,
                d.date_envoi,
                d.statut,
                d.priorite,
                d.niveau,
                d.type_devoir,
                
                -- Parent info
                p.id as parent_id,
                p.nom as parent_nom,
                p.prenom as parent_prenom,
                p.email as parent_email,
                
                -- Enfant info
                e.id as enfant_id,
                e.nom as enfant_nom,
                e.prenom as enfant_prenom,
                e.age as enfant_age,
                e.classe as enfant_classe,
                e.niveau as enfant_niveau,
                e.ecole as enfant_ecole,
                
                -- Assignation info
                da.id as assignation_id,
                da.date_assignation,
                da.date_limite,
                da.statut as statut_assignation,
                da.notes as notes_assignation
                
            FROM devoirs d
            JOIN users p ON d.parent_id = p.id
            JOIN enfants e ON d.enfant_id = e.id
            LEFT JOIN devoir_assignations da ON d.id = da.devoir_id AND da.tuteur_id = ?
            
            WHERE EXISTS (
                SELECT 1 FROM devoir_assignations da2 
                WHERE da2.devoir_id = d.id 
                AND da2.tuteur_id = ?
                AND da2.statut IN ('assigné', 'en_cours')
            )
            AND d.statut IN ('assigné', 'envoyé')
            
            ORDER BY 
                CASE 
                    WHEN da.date_limite IS NOT NULL AND da.date_limite < DATE('now') THEN 0
                    WHEN d.priorite = 'urgent' THEN 1
                    WHEN d.priorite = 'haute' THEN 2
                    ELSE 3
                END,
                da.date_limite ASC,
                d.date_remise ASC
        """, (current_user["id"], current_user["id"]))
        
        rows = cursor.fetchall()
        devoirs = []
        
        for row in rows:
            devoir = dict(row)
            
            # Formater les dates
            if devoir.get("date_envoi"):
                devoir["date_envoi_formatted"] = devoir["date_envoi"].split()[0] if devoir["date_envoi"] else ""
            
            if devoir.get("date_remise"):
                devoir["date_remise_formatted"] = devoir["date_remise"]
                
                # Vérifier si la deadline est dépassée
                try:
                    deadline = datetime.strptime(devoir["date_remise"], "%Y-%m-%d")
                    devoir["deadline_passed"] = deadline < datetime.now()
                    devoir["jours_restants"] = (deadline - datetime.now()).days
                except:
                    devoir["deadline_passed"] = False
                    devoir["jours_restants"] = None
            
            # Récupérer les fichiers du devoir
            cursor.execute("""
                SELECT * FROM devoir_fichiers 
                WHERE devoir_id = ?
                ORDER BY uploaded_at
            """, (devoir["id"],))
            
            fichiers_rows = cursor.fetchall()
            devoir["fichiers"] = [dict(f) for f in fichiers_rows]
            
            # Ajouter une clé "nb_fichiers" pour compatibilité
            devoir["nb_fichiers"] = len(devoir["fichiers"])
            
            devoirs.append(devoir)
        
        conn.close()
        
        return devoirs  # Retourner directement le tableau
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération devoirs tuteur (mes-devoirs): {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")
@app.get("/tuteur/{tuteur_id}")
async def get_devoirs_assignes_tuteur(
    tuteur_id: int,
    current_user = Depends(get_current_user)
):
    """Récupérer tous les devoirs assignés à un tuteur"""
    try:
        # Vérifier que l'utilisateur est tuteur ou admin
        if current_user.get("role") not in ["tuteur", "professeur", "admin"]:
            raise HTTPException(403, "Accès réservé aux tuteurs, professeurs et administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Récupérer les devoirs assignés à ce tuteur
        cursor.execute("""
            SELECT 
                d.id as devoir_id,
                d.titre,
                d.description,
                d.matiere,
                d.date_remise,
                d.date_envoi,
                d.statut as statut_devoir,
                d.priorite,
                d.niveau,
                d.note,
                
                -- Assignation info
                da.id as assignation_id,
                da.date_assignation,
                da.date_limite,
                da.statut as statut_assignation,
                da.notes as notes_assignation,
                
                -- Parent info
                p.id as parent_id,
                p.nom as parent_nom,
                p.prenom as parent_prenom,
                p.email as parent_email,
                p.telephone as parent_telephone,
                
                -- Enfant info
                e.id as enfant_id,
                e.nom as enfant_nom,
                e.prenom as enfant_prenom,
                e.age as enfant_age,
                e.classe as enfant_classe,
                e.niveau as enfant_niveau,
                e.ecole as enfant_ecole,
                
                -- Fichiers count
                (SELECT COUNT(*) FROM devoir_fichiers df WHERE df.devoir_id = d.id) as nb_fichiers
                
            FROM devoir_assignations da
            JOIN devoirs d ON da.devoir_id = d.id
            JOIN users p ON d.parent_id = p.id
            JOIN enfants e ON d.enfant_id = e.id
            WHERE da.tuteur_id = ?
            AND da.statut IN ('assigné', 'en_cours')
            ORDER BY da.date_limite ASC, d.priorite DESC
        """, (tuteur_id,))
        
        rows = cursor.fetchall()
        devoirs = []
        
        for row in rows:
            devoir = dict(row)
            
            # Formater les dates
            if devoir["date_envoi"]:
                devoir["date_envoi_formatted"] = devoir["date_envoi"].split()[0] if devoir["date_envoi"] else ""
            
            if devoir["date_limite"]:
                devoir["date_limite_formatted"] = devoir["date_limite"]
                
                # Vérifier si la deadline est dépassée
                try:
                    deadline = datetime.strptime(devoir["date_limite"], "%Y-%m-%d")
                    devoir["deadline_passed"] = deadline < datetime.now()
                    devoir["jours_restants"] = (deadline - datetime.now()).days
                except:
                    devoir["deadline_passed"] = False
                    devoir["jours_restants"] = None
            
            # Récupérer les fichiers du devoir
            cursor.execute("""
                SELECT * FROM devoir_fichiers 
                WHERE devoir_id = ?
                ORDER BY uploaded_at
            """, (devoir["devoir_id"],))
            
            fichiers_rows = cursor.fetchall()
            devoir["fichiers"] = [dict(f) for f in fichiers_rows]
            
            devoirs.append(devoir)
        
        conn.close()
        
        return {
            "tuteur_id": tuteur_id,
            "devoirs": devoirs,
            "total": len(devoirs)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur récupération devoirs tuteur: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

@app.get("/admin/update-corrections-table")
async def update_corrections_table(current_user = Depends(get_current_user)):
    """Ajoute les colonnes manquantes à la table corrections"""
    try:
        if current_user.get("role") != "admin":
            raise HTTPException(403, "Accès réservé aux administrateurs")
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Liste des colonnes à ajouter
        columns_to_add = [
            ("type_correction", "TEXT DEFAULT 'correction_detaille'"),
            ("format_explication", "TEXT DEFAULT 'textuel'"),
            ("niveau_detail", "TEXT DEFAULT 'intermediaire'"),
            ("methode_resolution", "TEXT DEFAULT 'standard'"),
            ("points_cles", "TEXT DEFAULT ''"),
            ("erreurs_communes", "TEXT DEFAULT ''"),
            ("conseils_pratiques", "TEXT DEFAULT ''"),
            ("ressources_complementaires", "TEXT DEFAULT ''"),
            ("temps_estime_eleve", "TEXT")
        ]
        
        added_columns = []
        
        for column_name, column_type in columns_to_add:
            try:
                # Vérifier si la colonne existe déjà
                cursor.execute(f"PRAGMA table_info(corrections)")
                columns = cursor.fetchall()
                column_exists = any(col[1] == column_name for col in columns)
                
                if not column_exists:
                    cursor.execute(f"ALTER TABLE corrections ADD COLUMN {column_name} {column_type}")
                    added_columns.append(column_name)
                    logger.info(f"✅ Colonne ajoutée: {column_name}")
                else:
                    logger.info(f"✅ Colonne existe déjà: {column_name}")
                    
            except Exception as e:
                logger.error(f"❌ Erreur ajout colonne {column_name}: {str(e)}")
        
        conn.commit()
        conn.close()
        
        return {
            "success": True,
            "message": "Table corrections mise à jour",
            "added_columns": added_columns,
            "total_added": len(added_columns)
        }
        
    except Exception as e:
        logger.error(f"❌ Erreur mise à jour table corrections: {str(e)}")
        raise HTTPException(500, f"Erreur serveur: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)