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
    if request.args.get('source') == 'extension':
        session['auth_source'] = 'extension'
    redirect_uri = url_for('auth_google', _external=True)
    
    # Ambil redirect URL dari Authlib
    resp = oauth.google.authorize_redirect(redirect_uri, nonce=nonce)
    google_url = resp.headers.get('Location')
    
    # Kembalikan halaman HTML perantara agar browser menyimpan session cookie dengan benar
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Redirecting to Google...</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background-color: #0f172a;
                color: white;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }}
            .card {{
                background: #1e293b;
                border: 1px solid #38bdf8;
                padding: 30px;
                border-radius: 12px;
                text-align: center;
                box-shadow: 0 4px 20px rgba(0,0,0,0.5);
                max-width: 400px;
            }}
            h1 {{ color: #38bdf8; margin-bottom: 10px; font-size: 20px; }}
            p {{ color: #94a3b8; font-size: 14px; }}
            .loader {{
                border: 3px solid #1e293b;
                border-top: 3px solid #38bdf8;
                border-radius: 50%;
                width: 24px;
                height: 24px;
                animation: spin 1s linear infinite;
                margin: 15px auto 0 auto;
            }}
            @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
        </style>
        <script>
            window.onload = function() {{
                setTimeout(() => {{
                    window.location.href = "{google_url}";
                }}, 300);
            }};
        </script>
    </head>
    <body>
        <div class="card">
            <h1>Menghubungkan ke Google...</h1>
            <p>Harap tunggu sebentar, Anda sedang dialihkan.</p>
            <div class="loader"></div>
        </div>
    </body>
    </html>
    """
    return html_content


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

    # Cek jika berasal dari extension
    auth_source = session.pop('auth_source', None)
    if auth_source == 'extension':
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Authentication Successful</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background-color: #0f172a;
                    color: white;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }}
                .card {{
                    background: #1e293b;
                    border: 1px solid #38bdf8;
                    padding: 30px;
                    border-radius: 12px;
                    text-align: center;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.5);
                    max-width: 400px;
                }}
                h1 {{ color: #38bdf8; margin-bottom: 10px; font-size: 24px; }}
                p {{ color: #94a3b8; font-size: 14px; margin-bottom: 20px; }}
                .loader {{
                    border: 4px solid #1e293b;
                    border-top: 4px solid #38bdf8;
                    border-radius: 50%;
                    width: 30px;
                    height: 30px;
                    animation: spin 1s linear infinite;
                    margin: 20px auto;
                }}
                @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
            </style>
        </head>
        <body>
            <div class="card">
                <h1>✓ Login Berhasil</h1>
                <p>Menghubungkan akun Anda dengan extension...</p>
                <div class="loader"></div>
                <!-- Data container for Content Script -->
                <div id="auth-data" 
                     data-token="{token}" 
                     data-nama="{user_data['nama']}" 
                     data-email="{user_data['email']}" 
                     data-role="{user_data.get('role', 'user')}"
                     style="display: none;">
                </div>
            </div>
            <script>
                // Auto close tab after a short delay
                setTimeout(() => {{
                    window.close();
                }}, 1500);
            </script>
        </body>
        </html>
        """
        return html_content

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