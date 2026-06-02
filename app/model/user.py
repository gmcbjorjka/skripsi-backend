# user.py
import secrets
from datetime import datetime

class User:
    def __init__(self, nama, email, password, role, foto_profil):
        self.nama = nama
        self.email = email
        self.password = password
        self.role = role
        self.foto_profil = foto_profil
        self.api_key = secrets.token_hex(32)
        self.verification_token = secrets.token_urlsafe(32)
        self.is_verified = False
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def to_dict(self):
        return {
            "nama": self.nama,
            "email": self.email,
            "password": self.password,
            "role": self.role,
            "foto_profil": self.foto_profil,
            "api_key": self.api_key,
            "verification_token": self.verification_token,
            "is_verified": self.is_verified,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
