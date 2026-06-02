import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    # Load dari .env
    MONGO_URI = str(os.environ.get("MONGO_URI"))
    JWT_SECRET_KEY = str(os.environ.get("JWT_SECRET"))
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=2)
    API_KEY = os.environ.get("API_KEY")
    # Upload config
    UPLOAD_FOLDER = os.path.join(basedir, os.environ.get("UPLOAD_FOLDER", "upload"))
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB
    GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID_WEB")  # <- Pastikan ini ditambahkan
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")  # <- Ini juga

    MAIL_SERVER = os.environ.get("MAIL_SERVER")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER")
