from flask import redirect, url_for, session, request, jsonify
from app import oauth, google, mongo
from app.model.user import User  # ✅ Import konsisten dan benar
from flask_jwt_extended import create_access_token
import secrets
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
import os


def login_google():
    nonce = secrets.token_urlsafe(16)
    session['nonce'] = nonce
    redirect_uri = url_for('auth_google', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)


def auth_google():
    token = oauth.google.authorize_access_token()
    nonce = session.pop('nonce', None)
    user_info = oauth.google.parse_id_token(token, nonce=nonce)

    # Cek apakah user sudah ada
    existing_user = mongo.db.user.find_one({"email": user_info['email']})

    if not existing_user:
        # Buat user baru
        nama = user_info['name']
        email = user_info['email']
        foto_profil = user_info['picture']
        role = "user"
        password = ""

        user = User(nama, email, password, role, foto_profil)
        mongo.db.user.insert_one(user.to_dict())
        user_data = user.to_dict()
    else:
        user_data = existing_user

    token = create_access_token(identity=str(user_data['_id']))
    session['user'] = {
        "nama": user_data['nama'],
        "email": user_data['email'],
        "foto_profil": user_data['foto_profil'],
        "token": token
    }

    return redirect('/')


def auth_google_flutter():
    try:
        data = request.get_json()
        print("Received JSON:", data)

        id_token = data.get('id_token')
        print("Received id_token:", id_token)

        if not id_token:
            return jsonify({'error': 'Missing id_token'}), 400

        # Verifikasi token Google
        idinfo = google_id_token.verify_oauth2_token(
            id_token,
            google_requests.Request(),
            os.environ.get("GOOGLE_CLIENT_ID_WEB")
        )

        email = idinfo['email']
        nama = idinfo.get('name', '')
        foto_profil = idinfo.get('picture', '')

        # Cari user di database
        existing_user = mongo.db.user.find_one({"email": email})

        if not existing_user:
            # Buat user baru
            user = User(nama, email, "", "user", foto_profil)
            result = mongo.db.user.insert_one(user.to_dict())
            # Ambil user baru dengan _id hasil insert
            user_data = mongo.db.user.find_one({"_id": result.inserted_id})
        else:
            user_data = existing_user

        # Buat token JWT dengan identity _id dari user_data
        token = create_access_token(identity=str(user_data['_id']))

        return jsonify({
            'token': token,
            'nama': user_data['nama'],
            'email': user_data['email'],
            'foto_profil': user_data['foto_profil'],
            'role': user_data.get('role', 'user')  # Pastikan ada role
        })

    except Exception as e:
        print("Error during Google auth:", str(e))
        traceback.print_exc()
        return jsonify({'error': 'Token tidak valid', 'details': str(e)}), 400