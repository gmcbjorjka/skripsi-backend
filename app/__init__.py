from flask import Flask
from config import Config
from flask_pymongo import PyMongo
from flask_jwt_extended import JWTManager
import socket
from authlib.integrations.flask_client import OAuth
import os
from flask_mail import Mail
from flask_cors import CORS

app = Flask(__name__)
app.config.from_object(Config)

# Aktifkan CORS – izinkan request dari browser extension (chrome-extension://)
CORS(app, resources={r"/*": {"origins": "*"}})

# setelah app dibuat
mail = Mail(app)

# Pastikan ada secret key untuk session Flask
app.secret_key = os.environ.get("SECRET_KEY", "ini_rahasia_buat_session")

# Setup MongoDB
mongo = PyMongo(app)

# Setup JWT
jwt = JWTManager(app)

# Setup OAuth
oauth = OAuth(app)

google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'},
)

# Import Model (model hanya class biasa)
from app.model import user, report

# Import Routes
from app import routes

if __name__ == "__main__":
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"Server running at: http://{local_ip}:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)