from app import app
from app.controller import UserController, OAuthController, CyrillicController, ReportController
from flask import Flask, request, jsonify, send_from_directory
import os
from config import Config
from flask_jwt_extended import jwt_required,get_jwt_identity
from app.api_service import require_api_key
from app import mongo
from bson import ObjectId
from app import response 
from datetime import datetime
from werkzeug.utils import secure_filename






@app.route('/')
def index():
    return jsonify({
        'message': 'Guard Scan View API',
        'version': '1.0.0',
        'description': 'API untuk URL scanning dan Cyrillic character analysis'
    })


# Routes untuk post, dosen, artikel, dan pelabuhan telah dihapus
# Project ini fokus pada User Management, OAuth, dan Cyrillic Support

@app.route('/user/register', methods=['POST'])
def register_user():
    return UserController.register()

@app.route('/user/login', methods=['POST'])
def login_user():
    return UserController.login()

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    print(f"Looking for: {full_path}")  # Debug log
    if not os.path.exists(full_path):
        print("File not found")
        return jsonify({'error': 'File not found'}), 404
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- Google OAuth Routes
@app.route('/login/google')
def login_google():
    return OAuthController.login_google()

@app.route('/auth/google')
def auth_google():
    return OAuthController.auth_google()

@app.route('/auth/google/flutter', methods=['POST'])
def auth_google_flutter_route():
    from app.controller.OAuthController import auth_google_flutter
    return auth_google_flutter()

@app.route('/user/forgot-password', methods=['POST'])
def forgot_password_route():
    return UserController.forgot_password()

@app.route('/user/reset-password', methods=['POST'])
def reset_password_route():
    return UserController.reset_password()


@app.route('/verify-email', methods=['GET'])
def verify_email_route():
    return UserController.verify_email()

@app.route('/user/login-history', methods=['GET'])
@jwt_required()
def get_login_history():
    try:
        user_id = get_jwt_identity()
        print(f"🔒 Get history for user_id: {user_id}")

        history = list(
            mongo.db.login_history.find({"user_id": ObjectId(user_id)}).sort("login_time", -1)
        )

        for h in history:
            h["_id"] = str(h["_id"])
            h["user_id"] = str(h["user_id"])
            h["login_time"] = h["login_time"].isoformat()
            h["device"] = h.get("device", "unknown")
            h["ip_address"] = h.get("ip_address", "-")

        return response.success(history, "Riwayat login ditemukan")
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return response.badRequest([], f"Error: {str(e)}")


# Routes untuk penimbangan telah dihapus - tidak digunakan

@app.route('/user/change-password', methods=['POST'])
def change_password_route():
    from app.controller.UserController import change_password
    return change_password()

@app.route('/user/upload-profile-picture', methods=['POST'])
@jwt_required()
def upload_profile_picture():
    try:
        user_id = get_jwt_identity()
        print("✅ JWT user_id:", user_id)

        if not user_id:
            return response.error([], "User tidak ditemukan di JWT", 401)

        print("✅ Request form:", request.form)
        print("✅ Request files:", request.files)

        file = request.files.get('file')
        if not file or file.filename == '':
            return response.error([], "File tidak ditemukan atau kosong", 400)

        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()
        new_filename = f"{user_id}{ext}"

        upload_path = app.config['UPLOAD_FOLDER']
        os.makedirs(upload_path, exist_ok=True)
        save_path = os.path.join(upload_path, new_filename)

        file.save(save_path)
        print(f"✅ File disimpan di: {save_path}")

        mongo.db.user.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": {"foto_profil": new_filename}}
        )

        user = mongo.db.user.find_one({"_id": ObjectId(user_id)})
        user['id'] = str(user['_id'])
        user.pop('_id', None)
        user.pop('password', None)

        return response.success(user, "Foto profil berhasil diperbarui")
    except Exception as e:
        print("❌ Upload error:", e)
        return response.error([], f"Upload gagal: {str(e)}", 500)
    

@app.route('/user/update-name', methods=['POST'])
@jwt_required()
def update_name():
    user_id = get_jwt_identity()
    data = request.get_json()
    new_name = data.get('nama', '').strip()

    print(f"🟢 user_id: {user_id}")
    print(f"🟢 request data: {data}")
    print(f"🟢 new_name: {new_name}")

    if not new_name:
        return jsonify(success=False, message="Nama tidak boleh kosong"), 400

    # ✅ PASTIKAN SAMA DENGAN UPLOAD!
    users = mongo.db.user

    try:
        filter_query = {'_id': ObjectId(user_id)}
    except:
        filter_query = {'_id': user_id}

    result = users.update_one(filter_query, {'$set': {'nama': new_name}})
    if result.matched_count == 0:
        filter_query = {'_id': user_id}
        result = users.update_one(filter_query, {'$set': {'nama': new_name}})

    print(f"🟢 matched_count: {result.matched_count}")
    print(f"🟢 modified_count: {result.modified_count}")

    if result.matched_count >= 1:
        updated_user = users.find_one(filter_query)
        return jsonify(success=True, data={'nama': updated_user['nama']}, message="Nama berhasil diperbarui"), 200
    else:
        return jsonify(success=False, message="User tidak ditemukan"), 400


# --- User Management Routes ---
@app.route('/user/all', methods=['GET'])
@jwt_required()
def get_all_users_route():
    return UserController.get_all_users()

@app.route('/user/<user_id>/role', methods=['POST'])
@jwt_required()
def change_role_route(user_id):
    return UserController.change_role(user_id)

@app.route('/user/<user_id>/toggle-status', methods=['POST'])
@jwt_required()
def toggle_user_status_route(user_id):
    return UserController.toggle_user_status(user_id)

@app.route('/user/<user_id>', methods=['DELETE'])
@jwt_required()
def delete_user_route(user_id):
    return UserController.delete_user(user_id)



# --- Cyrillic Character Routes ---
@app.route('/cyrillic/analyze', methods=['POST'])
def analyze_cyrillic_route():
    """
    Analisis karakter Cyrillic
    Input: JSON dengan field 'text'
    Output: Detail setiap karakter dengan Unicode info
    """
    return CyrillicController.analyze_cyrillic()


@app.route('/cyrillic/convert', methods=['POST'])
def convert_cyrillic_route():
    """
    Konversi text ke Cyrillic dan tampilkan detail karakter
    Input: JSON dengan field 'text'
    Output: Text yang sudah benar dengan Unicode info
    """
    return CyrillicController.convert_to_cyrillic()


@app.route('/cyrillic/punycode/decode', methods=['POST'])
def decode_punycode_route():
    """
    Decode Punycode (xn--) ke Unicode
    """
    return CyrillicController.decode_punycode()


@app.route('/cyrillic/punycode/encode', methods=['POST'])
def encode_punycode_route():
    """
    Encode Unicode ke Punycode (xn--)
    """
    return CyrillicController.encode_punycode()


# --- URL Report & Scanning Routes ---
@app.route('/report/scan', methods=['POST'])
def scan_url_route():
    """
    Scan URL untuk mendeteksi Phishing
    POST /report/scan
    Body: { "url": "http://example.com", "details": {} }
    """
    return ReportController.scan_url()


@app.route('/report/submit', methods=['POST'])
def submit_report_route():
    """
    Kirim laporan phishing dari form user
    POST /report/submit
    """
    return ReportController.submit_user_report()


@app.route('/report/all', methods=['GET'])
def get_all_reports_route():
    """
    Dapatkan semua report scan
    GET /report/all?skip=0&limit=50
    """
    return ReportController.get_all_reports()


@app.route('/report/<report_id>', methods=['GET'])
def get_report_route(report_id):
    """
    Dapatkan detail report berdasarkan ID
    GET /report/<report_id>
    """
    return ReportController.get_report_by_id(report_id)


@app.route('/report/statistics', methods=['GET'])
def get_statistics_route():
    """
    Dapatkan statistik scan
    GET /report/statistics
    """
    return ReportController.get_statistics()


@app.route('/report/<report_id>', methods=['DELETE'])
def delete_report_route(report_id):
    """
    Hapus report berdasarkan ID
    DELETE /report/<report_id>
    """
    return ReportController.delete_report(report_id)


@app.route('/report/<report_id>/validate', methods=['POST'])
def validate_report_route(report_id):
    """
    Validasi report
    POST /report/<report_id>/validate
    """
    return ReportController.validate_report(report_id)


@app.route('/blacklist', methods=['POST'])
def add_to_blacklist_route():
    return ReportController.add_to_blacklist()


@app.route('/blacklist', methods=['GET'])
def get_blacklist_route():
    return ReportController.get_blacklist()


@app.route('/blacklist/<blacklist_id>', methods=['DELETE'])
def remove_from_blacklist_route(blacklist_id):
    return ReportController.remove_from_blacklist(blacklist_id)


@app.route('/history', methods=['POST'])
def add_to_history_route():
    return ReportController.add_to_history()


@app.route('/history', methods=['GET'])
def get_history_route():
    return ReportController.get_history()


@app.route('/history', methods=['DELETE'])
def clear_history_route():
    return ReportController.clear_history()


