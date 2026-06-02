from flask import request, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from app import mongo, response, mail
from app.model.user import User
from bson import ObjectId
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import pytz 
import platform
import socket
import requests
import os
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_mail import Message
import random
from datetime import datetime


# --- REGISTER
def register():
    try:
        nama = request.form.get('nama')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role') or '3'  # Default otomatis '3'
        file = request.files.get('foto_profil')  # Boleh kosong

        if not nama or not email or not password:
            return response.error([], "Nama, email, dan password wajib diisi")

        if mongo.db.user.find_one({"email": email}):
            return response.error([], "Email sudah digunakan")

        hashed_pw = generate_password_hash(password)

        if file:
            filename = secure_filename(
                email.lower().replace("@", "_").replace(".", "_") +
                os.path.splitext(file.filename)[1]
            )
            filepath = os.path.join(os.getenv("UPLOAD_FOLDER"), filename)
            file.save(filepath)
        else:
            filename = ""  # Jika tidak ada foto, kosongkan

        user = User(nama, email, hashed_pw, role, filename)
        inserted = mongo.db.user.insert_one(user.to_dict())

        verification_link = f"{request.host_url}verify-email?token={user.verification_token}"
        msg = Message(
            "Verifikasi Email Anda",
            recipients=[email],
            body=f"Halo {nama},\n\nKlik link berikut untuk verifikasi email Anda:\n{verification_link}"
        )
        mail.send(msg)

        return response.success({
            "id": str(inserted.inserted_id),
            "api_key": user.api_key
        }, "Registrasi berhasil")

    except Exception as e:
        print(e)
        return response.error([], "Gagal registrasi user")


# --- LOGIN
def login():
    try:
        if request.is_json:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            device_info = data.get('device_info') or "Unknown"
        else:
            email = request.form.get('email')
            password = request.form.get('password')
            device_info = request.form.get('device_info') or "Unknown"

        if not email or not password:
            return response.error([], "Email dan password harus diisi")

        user = mongo.db.user.find_one({"email": email})
        if not user:
            return response.error([], "User tidak ditemukan")

        now = datetime.utcnow()

        # Cek apakah akun sedang diblokir
        if user.get("login_block_until") and user["login_block_until"] > now:
            remaining_seconds = (user["login_block_until"] - now).total_seconds()
            return response.error({
                "blocked": True,
                "blocked_until": user["login_block_until"].isoformat(),
                "remaining_seconds": remaining_seconds
            }, f"Akun diblokir sementara. Coba lagi nanti.")

        # Password salah
        if not check_password_hash(user['password'], password):
            failed_count = user.get("failed_login_count", 0) + 1

            update_fields = {
                "failed_login_count": failed_count,
                "last_failed_login": now,
            }

            if failed_count >= 3:
                update_fields["login_block_until"] = now + timedelta(minutes=1)
                update_fields["failed_login_count"] = 0  # reset counter

                # Kirim email peringatan
                device = platform.platform()
                hostname = socket.gethostname()
                ip_address = request.remote_addr
                location = get_ip_location(ip_address)

                msg = f"""
Hai {user['nama']},

Terdapat 3 kali percobaan login GAGAL ke akun Anda.

📅 Waktu: {now}
💻 Perangkat: {device}
🌐 IP Address: {ip_address}
📍 Lokasi: {location}

Jika ini bukan Anda, segera ubah password Anda.
"""
                mail.send(Message(
                    subject="Peringatan: Percobaan Login Gagal",
                    recipients=[email],
                    body=msg
                ))

            mongo.db.user.update_one({"_id": user["_id"]}, {"$set": update_fields})
            return response.error([], "Password salah")

        # Login berhasil
        access_token = create_access_token(identity=str(user['_id']))

        # Simpan riwayat login
        login_record = {
            "user_id": user["_id"],
            "email": user["email"],
            "device_info": device_info,
            "login_time": now,
            "ip_address": request.remote_addr
        }
        mongo.db.login_history.insert_one(login_record)

        user_data = {
            "id": str(user['_id']),
            "nama": user['nama'],
            "email": user['email'],
            "role": user['role'],
            "foto_profil": user['foto_profil'],
            "token": access_token
        }

        # Reset counter dan blokir jika ada
        mongo.db.user.update_one({"_id": user["_id"]}, {
            "$set": {"failed_login_count": 0},
            "$unset": {"login_block_until": "", "last_failed_login": ""}
        })

        return response.success(user_data, "Login berhasil")

    except Exception as e:
        print(e)
        return response.error([], "Gagal login")



def forgot_password():
    try:
        email = request.form.get("email")
        if not email:
            return response.error([], "Email harus diisi")

        user = mongo.db.user.find_one({"email": email})
        if not user:
            return response.error([], "Email tidak ditemukan")

        kode = str(random.randint(100000, 999999))

        # Simpan kode
        mongo.db.user.update_one(
            {"_id": user["_id"]},
            {"$set": {"reset_code": kode, "reset_code_created": datetime.utcnow()}}
        )

        # Kirim Email
        msg = Message("Kode Reset Password",
                      recipients=[email],
                      body=f"Kode verifikasi reset password kamu adalah: {kode}")
        mail.send(msg)

        return response.success({"email": email}, "Kode verifikasi dikirim ke email")
    except Exception as e:
        print(e)
        return response.error([], "Gagal mengirim email reset")

def reset_password():
    try:
        email = request.form.get("email")
        kode = request.form.get("kode")
        password = request.form.get("password")

        if not email or not kode or not password:
            return response.error([], "Semua field harus diisi")

        user = mongo.db.user.find_one({"email": email})
        if not user:
            return response.error([], "Email tidak ditemukan")

        # Cek kode
        if user.get("reset_code") != kode:
            return response.error([], "Kode verifikasi salah")

        hashed_pw = generate_password_hash(password)

        mongo.db.user.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "password": hashed_pw,
                    "updated_at": datetime.utcnow()
                },
                "$unset": {
                    "reset_code": "", "reset_code_created": ""
                }
            }
        )

        return response.success({}, "Password berhasil direset")
    except Exception as e:
        print(e)
        return response.error([], "Gagal reset password")

# Tambahkan fungsi baru
def verify_email():
    try:
        token = request.args.get("token")
        if not token:
            return render_template("verify_failed.html")

        user = mongo.db.user.find_one({"verification_token": token})
        if not user:
            return render_template("verify_failed.html")

        mongo.db.user.update_one(
            {"_id": user["_id"]},
            {
                "$set": {"is_verified": True, "updated_at": datetime.utcnow()},
                "$unset": {"verification_token": ""}
            }
        )

        return render_template("verify_success.html")
    except Exception as e:
        print(e)
        return render_template("verify_failed.html")

def get_ip_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            data = response.json()
            return f"{data.get('city', '')}, {data.get('region', '')}, {data.get('country', '')}"
        return "Lokasi tidak diketahui"
    except:
        return "Lokasi tidak diketahui"


@jwt_required()
def change_password():
    try:
        user_id = get_jwt_identity()
        data = request.get_json()

        old_password = data.get("old_password")
        new_password = data.get("new_password")

        if not old_password or not new_password:
            return response.error([], "Semua field harus diisi")

        user = mongo.db.user.find_one({"_id": ObjectId(user_id)})
        if not user:
            return response.error([], "User tidak ditemukan")

        if not check_password_hash(user['password'], old_password):
            return response.error([], "Kata sandi lama salah")

        new_hash = generate_password_hash(new_password)
        mongo.db.user.update_one({"_id": user['_id']}, {
            "$set": {
                "password": new_hash,
                "updated_at": datetime.utcnow()
            }
        })

        return response.success({}, "Kata sandi berhasil diubah")
    except Exception as e:
        print(e)
        return response.error([], "Gagal mengubah kata sandi")