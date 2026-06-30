"""
Report Controller - Handle URL Scanning dan Report Management
"""

from flask import request, jsonify
from app import mongo, response
from bson import ObjectId
from datetime import datetime
import re
import os
import numpy as np
import tldextract
import joblib
from flask_jwt_extended import jwt_required, get_jwt_identity

# Load ML Model
MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'model_ekstensi', 'hybrid_xgboost_phishing.joblib')
try:
    phishing_model = joblib.load(MODEL_PATH)
    print("✅ Hybrid ML Pipeline loaded successfully")
except Exception as e:
    print(f"❌ Failed to load Hybrid ML Pipeline: {e}")
    phishing_model = None

def extract_features(url):
    features = []
    features.append(len(url))                # panjang URL
    features.append(url.count('.'))           # jumlah titik
    features.append(url.count('-'))           # dash
    features.append(url.count('@'))           # @
    features.append(url.count('?'))           # ?
    features.append(url.count('='))           # =
    features.append(url.count('/'))           # slash
    features.append(url.count('http'))        # http count
    features.append(1 if 'https' in url else 0)  # https

    ext = tldextract.extract(url)
    features.append(len(ext.domain))          # panjang domain
    features.append(len(ext.subdomain))       # panjang subdomain

    return features

def validate_url(url):
    """
    Validasi format URL (termasuk karakter Unicode/Cyrillic)
    """
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[^\s:@/]+(?::[^\s:@/]*)?@)?'  # optional auth
        r'(?:(?:[^\s/?#:]+)\.)+[^\s/?#:]+|'   # domain
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return url_pattern.match(url) is not None


def predict_url(url, is_blacklisted):
    has_cyrillic = bool(re.search(r'[\u0400-\u04FF\u0500-\u052F]', url))
    result = 'Safe'
    confidence = 0.95
    is_suspicious = False
    
    if is_blacklisted:
        result = 'Phishing'
        confidence = 1.0
        is_suspicious = True
    elif phishing_model:
        try:
            try:
                prediction = phishing_model.predict([url])[0]
                proba = phishing_model.predict_proba([url])[0]
            except Exception as nlp_err:
                features = extract_features(url)
                X = np.array([features])
                prediction = phishing_model.predict(X)[0]
                proba = phishing_model.predict_proba(X)[0]
            
            if prediction == 1 or has_cyrillic:
                result = 'Phishing'
                is_suspicious = True
                if has_cyrillic:
                    confidence = 0.95
                else:
                    confidence = float(max(proba))
            else:
                result = 'Safe'
                confidence = float(max(proba))
        except Exception as e:
            suspicious_keywords = ['confirm', 'verify', 'update', 'login', 'account', 
                                  'password', 'secure', 'validate', 'paypal', 'amazon', 
                                  'apple', 'google', 'microsoft', 'bank']
            is_suspicious = any(keyword in url.lower() for keyword in suspicious_keywords) or has_cyrillic
            result = 'Phishing' if is_suspicious else 'Safe'
            confidence = 0.7 if is_suspicious and not has_cyrillic else 0.95
    else:
        suspicious_keywords = ['confirm', 'verify', 'update', 'login', 'account', 
                              'password', 'secure', 'validate', 'paypal', 'amazon', 
                              'apple', 'google', 'microsoft', 'bank']
        is_suspicious = any(keyword in url.lower() for keyword in suspicious_keywords) or has_cyrillic
        result = 'Phishing' if is_suspicious else 'Safe'
        confidence = 0.7 if is_suspicious and not has_cyrillic else 0.95

    details = {
        'confidence': confidence,
        'indicators': {
            'suspicious_keywords': is_suspicious,
            'domain_reputation': 'Unknown',
            'ssl_certificate': True if url.startswith('https') else False,
            'url_length': len(url),
            'has_cyrillic': has_cyrillic,
            'is_blacklisted': is_blacklisted
        }
    }
    return result, confidence, details


def scan_url():
    """
    Scan URL dan klasifikasi Phishing atau Safe
    POST /report/scan
    Request: {
        "url": "http://example.com/login",
        "details": {} (optional)
    }
    Response: Report hasil scan
    """
    try:
        data = request.get_json()
        
        if not data or 'url' not in data:
            return response.badRequest([], "URL field wajib diisi")
        
        url = data.get('url', '').strip()
        
        if not url:
            return response.badRequest([], "URL tidak boleh kosong")
            
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        if not validate_url(url):
            return response.badRequest([], "Format URL tidak valid")
        
        is_blacklisted = mongo.db.blacklist.find_one({"url": url}) is not None
        
        # Predict using helper
        result, confidence, details = predict_url(url, is_blacklisted)
        
        report_data = {
            'url': url,
            'result': result,
            'status': 'Validated',
            'user_id': ObjectId() if not hasattr(request, 'jwt_identity') else ObjectId(request.jwt_identity),
            'date': datetime.now(),
            'confidence': confidence,
            'is_user_report': False,
            'details': details
        }
        
        inserted = mongo.db.reports.insert_one(report_data)
        
        result_data = {
            'id': str(inserted.inserted_id),
            'url': url,
            'result': result,
            'status': 'Validated',
            'date': datetime.now().isoformat(),
            'confidence': confidence,
            'details': details
        }
        
        return response.success(result_data, "URL scan selesai")
    
    except Exception as e:
        print(f"Error scanning URL: {str(e)}")
        return response.error([], f"Gagal scan URL: {str(e)}")


def submit_user_report():
    """
    Kirim laporan phishing oleh user lewat ekstensi
    POST /report/submit
    """
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return response.badRequest([], "URL field wajib diisi")
            
        url = data.get('url', '').strip()
        if not url:
            return response.badRequest([], "URL tidak boleh kosong")

        reason = data.get('reason', '')
        description = data.get('description', '')
        reporter_email = data.get('email', '')

        # Standardize URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        is_blacklisted = mongo.db.blacklist.find_one({"url": url}) is not None
        
        # Predict using helper
        result, confidence, details = predict_url(url, is_blacklisted)

        # Extend details with reason and description
        details['user_report_reason'] = reason
        details['user_report_description'] = description

        report_data = {
            "url": url,
            "result": result,
            "status": "Pending",
            "date": datetime.utcnow(),
            "confidence": float(confidence),
            "reporter": reporter_email if reporter_email else "User Ekstensi",
            "is_user_report": True,
            "details": details
        }
        
        inserted = mongo.db.reports.insert_one(report_data)
        
        return response.success({"id": str(inserted.inserted_id)}, "Laporan berhasil dikirim")
        
    except Exception as e:
        print(f"Error submitting user report: {str(e)}")
        return response.error([], f"Gagal mengirim laporan: {str(e)}")


def get_all_reports():
    """
    Dapatkan semua report
    GET /report/all
    """
    try:
        skip = request.args.get('skip', 0, type=int)
        limit = request.args.get('limit', 50, type=int)
        
        # Ensure database indexes exist for fast sorting and searching
        try:
            mongo.db.reports.create_index([('date', -1)])
            mongo.db.blacklist.create_index([('url', 1)])
        except Exception as idx_err:
            print(f"Index creation warning: {idx_err}")

        reports = list(mongo.db.reports.find({"is_user_report": True}).sort('date', -1).skip(skip).limit(limit))
        total = mongo.db.reports.count_documents({"is_user_report": True})
        
        # OPTIMIZATION: Bulk fetch blacklist status in a single query
        urls_in_reports = [r.get('url', '') for r in reports if r.get('url')]
        blacklisted_records = list(mongo.db.blacklist.find({"url": {"$in": urls_in_reports}}, {"url": 1}))
        blacklisted_set = {b.get('url') for b in blacklisted_records if b.get('url')}

        result = []
        for report in reports:
            url = report.get('url', '')
            is_blacklisted = url in blacklisted_set
            result.append({
                'id': str(report.get('_id')),
                'url': url,
                'result': report.get('result', ''),
                'status': report.get('status', 'Pending'),
                'date': report.get('date', datetime.utcnow()).isoformat(),
                'confidence': report.get('confidence', 0),
                'reporter': report.get('reporter', 'User Ekstensi'),
                'is_blacklisted': is_blacklisted
            })
        
        return response.success({
            'reports': result,
            'total': total,
            'page': skip // limit + 1,
            'limit': limit
        }, "Report berhasil diambil")
    
    except Exception as e:
        print(f"Error getting reports: {str(e)}")
        return response.error([], f"Gagal mengambil report: {str(e)}")


def get_report_by_id(report_id):
    """
    Dapatkan report berdasarkan ID
    GET /report/<report_id>
    """
    try:
        report = mongo.db.reports.find_one({'_id': ObjectId(report_id)})
        
        if not report:
            return response.notFound([], "Report tidak ditemukan")
        
        result = {
            'id': str(report.get('_id')),
            'url': report.get('url', ''),
            'result': report.get('result', ''),
            'status': report.get('status', 'Pending'),
            'date': report.get('date', datetime.utcnow()).isoformat(),
            'confidence': report.get('confidence', 0),
            'reporter': report.get('reporter', 'User Ekstensi'),
            'details': report.get('details', {})
        }
        
        return response.success(result, "Report ditemukan")
    
    except Exception as e:
        print(f"Error getting report: {str(e)}")
        return response.error([], f"Gagal mengambil report: {str(e)}")


def get_statistics():
    """
    Dapatkan statistik scan
    GET /report/statistics
    """
    try:
        total_scans = mongo.db.reports.count_documents({"is_user_report": True})
        phishing_count = mongo.db.reports.count_documents({'result': 'Phishing', "is_user_report": True})
        safe_count = mongo.db.reports.count_documents({'result': 'Safe', "is_user_report": True})
        
        # Calculate percentage
        phishing_percent = (phishing_count / total_scans * 100) if total_scans > 0 else 0
        safe_percent = (safe_count / total_scans * 100) if total_scans > 0 else 0
        
        stats = {
            'total_urls_scanned': total_scans,
            'phishing_detected': phishing_count,
            'safe_urls': safe_count,
            'phishing_percentage': round(phishing_percent, 1),
            'safe_percentage': round(safe_percent, 1)
        }
        
        return response.success(stats, "Statistik berhasil diambil")
    
    except Exception as e:
        print(f"Error getting statistics: {str(e)}")
        return response.error([], f"Gagal mengambil statistik: {str(e)}")


def delete_report(report_id):
    """
    Hapus report berdasarkan ID
    DELETE /report/<report_id>
    """
    try:
        result = mongo.db.reports.delete_one({'_id': ObjectId(report_id)})
        if result.deleted_count == 0:
            return response.notFound([], "Report tidak ditemukan")
        return response.success({}, "Report berhasil dihapus")
    except Exception as e:
        print(f"Error deleting report: {str(e)}")
        return response.error([], f"Gagal menghapus report: {str(e)}")


def validate_report(report_id):
    """
    Validasi report (ubah status dari Pending ke Validated)
    POST /report/<report_id>/validate
    """
    try:
        result = mongo.db.reports.update_one(
            {'_id': ObjectId(report_id)},
            {'$set': {'status': 'Validated'}}
        )
        if result.matched_count == 0:
            return response.notFound([], "Report tidak ditemukan")
        return response.success({}, "Report berhasil divalidasi")
    except Exception as e:
        print(f"Error validating report: {str(e)}")
        return response.error([], f"Gagal memvalidasi report: {str(e)}")


def add_to_blacklist():
    """
    Tambah URL ke daftar hitam
    POST /blacklist
    Body: { "url": "http://example.com/login" }
    """
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return response.badRequest([], "URL field wajib diisi")
        
        url = data.get('url', '').strip()
        if not url:
            return response.badRequest([], "URL tidak boleh kosong")
            
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Hindari duplikasi di blacklist
        existing = mongo.db.blacklist.find_one({"url": url})
        if existing:
            return response.success({"id": str(existing['_id'])}, "URL sudah ada di daftar hitam")
            
        blacklist_data = {
            "url": url,
            "date_added": datetime.utcnow()
        }
        
        inserted = mongo.db.blacklist.insert_one(blacklist_data)
        
        # Cari juga report dengan URL ini dan update agar berstatus Phishing dan Validated
        mongo.db.reports.update_many(
            {"url": url},
            {"$set": {"result": "Phishing", "status": "Validated", "confidence": 1.0}}
        )
        
        return response.success({"id": str(inserted.inserted_id)}, "URL berhasil ditambahkan ke daftar hitam")
    except Exception as e:
        print(f"Error adding to blacklist: {str(e)}")
        return response.error([], f"Gagal menambahkan ke daftar hitam: {str(e)}")


def get_blacklist():
    """
    Dapatkan semua daftar hitam
    GET /blacklist
    """
    try:
        blacklist = list(mongo.db.blacklist.find().sort('date_added', -1))
        result = []
        for b in blacklist:
            result.append({
                "id": str(b['_id']),
                "url": b.get("url", ""),
                "date_added": b.get("date_added", datetime.utcnow()).isoformat()
            })
        return response.success(result, "Blacklist berhasil diambil")
    except Exception as e:
        print(f"Error getting blacklist: {str(e)}")
        return response.error([], f"Gagal mengambil blacklist: {str(e)}")


def remove_from_blacklist(blacklist_id):
    """
    Hapus URL dari daftar hitam
    DELETE /blacklist/<blacklist_id>
    """
    try:
        result = mongo.db.blacklist.delete_one({'_id': ObjectId(blacklist_id)})
        if result.deleted_count == 0:
            return response.notFound([], "Daftar hitam tidak ditemukan")
        return response.success({}, "URL berhasil dihapus dari daftar hitam")
    except Exception as e:
        print(f"Error removing from blacklist: {str(e)}")
        return response.error([], f"Gagal menghapus dari daftar hitam: {str(e)}")


@jwt_required(optional=True)
def add_to_history():
    """
    Simpan riwayat deteksi ke koleksi 'riwayat'
    POST /history
    """
    try:
        user_id = get_jwt_identity()
        if not user_id:
            # Jika guest, tidak perlu simpan ke backend
            return response.success({}, "Scan guest selesai (tidak disimpan ke backend)")

        user = mongo.db.user.find_one({"_id": ObjectId(user_id)})
        if not user:
            return response.notFound([], "Pengguna tidak ditemukan")
            
        user_email = user.get("email")
        if not user_email:
            return response.error([], "Email pengguna tidak valid")

        data = request.get_json()
        url = data.get("url", "").strip()
        result = data.get("result", "Safe")
        status = data.get("status", "safe")
        risk_score = data.get("riskScore", 0.0)

        # Standar keamanan URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        history_data = {
            "user_email": user_email,
            "url": url,
            "result": result,
            "status": status,
            "riskScore": float(risk_score),
            "date": datetime.utcnow()
        }

        mongo.db.riwayat.insert_one(history_data)

        return response.success({}, "Riwayat berhasil disimpan")
    except Exception as e:
        print(f"Error adding to history: {str(e)}")
        return response.error([], f"Gagal menyimpan riwayat: {str(e)}")


@jwt_required()
def get_history():
    """
    Dapatkan riwayat deteksi pengguna
    GET /history
    """
    try:
        user_id = get_jwt_identity()
        user = mongo.db.user.find_one({"_id": ObjectId(user_id)})
        if not user:
            return response.notFound([], "Pengguna tidak ditemukan")
            
        user_email = user.get("email")
        history = list(mongo.db.riwayat.find({"user_email": user_email}).sort('date', -1).limit(10))

        result = []
        for h in history:
            result.append({
                "id": str(h["_id"]),
                "url": h.get("url", ""),
                "status": h.get("status", "safe"),
                "riskScore": h.get("riskScore", 0.0),
                "timestamp": h.get("date", datetime.utcnow()).isoformat()
            })

        return response.success(result, "Riwayat berhasil diambil")
    except Exception as e:
        print(f"Error getting history: {str(e)}")
        return response.error([], f"Gagal mengambil riwayat: {str(e)}")


@jwt_required()
def clear_history():
    """
    Hapus seluruh riwayat deteksi pengguna
    DELETE /history
    """
    try:
        user_id = get_jwt_identity()
        user = mongo.db.user.find_one({"_id": ObjectId(user_id)})
        if not user:
            return response.notFound([], "Pengguna tidak ditemukan")
            
        user_email = user.get("email")
        mongo.db.riwayat.delete_many({"user_email": user_email})

        return response.success({}, "Seluruh riwayat berhasil dihapus")
    except Exception as e:
        print(f"Error clearing history: {str(e)}")
        return response.error([], f"Gagal menghapus riwayat: {str(e)}")


