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
        
        # Check for Cyrillic characters (IDN Homograph attack indicator)
        has_cyrillic = bool(re.search(r'[\u0400-\u04FF\u0500-\u052F]', url))

        # Integrate ML model
        result = 'Safe'
        confidence = 0.95
        is_suspicious = False
        
        if phishing_model:
            try:
                # Coba prediksi dengan raw URL (tipe pipeline NLP scikit-learn standard)
                try:
                    prediction = phishing_model.predict([url])[0]
                    proba = phishing_model.predict_proba([url])[0]
                    print("🤖 Prediksi menggunakan raw URL string (Hybrid ML Pipeline)")
                except Exception as nlp_err:
                    # Fallback: jika gagal, coba dengan lexical features (tipe tabular model sebelumnya)
                    print(f"⚠️ Hybrid ML Pipeline prediction failed ({nlp_err}), trying fallback tabular features...")
                    features = extract_features(url)
                    X = np.array([features])
                    prediction = phishing_model.predict(X)[0]
                    proba = phishing_model.predict_proba(X)[0]
                    print("🤖 Prediksi menggunakan tabular lexical features")
                
                if prediction == 1 or has_cyrillic:
                    result = 'Phishing'
                    is_suspicious = True
                    if has_cyrillic:
                        confidence = 0.95 # High confidence for homograph attack
                    else:
                        confidence = float(max(proba))
                else:
                    result = 'Safe'
                    confidence = float(max(proba))
            except Exception as e:
                print(f"ML Prediction Error: {e}")
                # Fallback to keyword classification if ML fails
                suspicious_keywords = ['confirm', 'verify', 'update', 'login', 'account', 
                                      'password', 'secure', 'validate', 'paypal', 'amazon', 
                                      'apple', 'google', 'microsoft', 'bank']
                is_suspicious = any(keyword in url.lower() for keyword in suspicious_keywords) or has_cyrillic
                result = 'Phishing' if is_suspicious else 'Safe'
                confidence = 0.7 if is_suspicious and not has_cyrillic else 0.95
        else:
            # Fallback to keyword classification if model not loaded
            suspicious_keywords = ['confirm', 'verify', 'update', 'login', 'account', 
                                  'password', 'secure', 'validate', 'paypal', 'amazon', 
                                  'apple', 'google', 'microsoft', 'bank']
            is_suspicious = any(keyword in url.lower() for keyword in suspicious_keywords) or has_cyrillic
            result = 'Phishing' if is_suspicious else 'Safe'
            confidence = 0.7 if is_suspicious and not has_cyrillic else 0.95
        
        # Simulasi detection details
        details = {
            'confidence': confidence,
            'indicators': {
                'suspicious_keywords': is_suspicious,
                'domain_reputation': 'Unknown',
                'ssl_certificate': True if url.startswith('https') else False,
                'url_length': len(url),
                'has_cyrillic': has_cyrillic
            }
        }
        
        report_data = {
            'url': url,
            'result': result,
            'status': 'Validated',
            'user_id': ObjectId() if not hasattr(request, 'jwt_identity') else ObjectId(request.jwt_identity),
            'date': datetime.now(),
            'confidence': confidence,
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


def get_all_reports():
    """
    Dapatkan semua report
    GET /report/all
    """
    try:
        skip = request.args.get('skip', 0, type=int)
        limit = request.args.get('limit', 50, type=int)
        
        reports = list(mongo.db.reports.find().sort('date', -1).skip(skip).limit(limit))
        total = mongo.db.reports.count_documents({})
        
        result = []
        for report in reports:
            result.append({
                'id': str(report.get('_id')),
                'url': report.get('url', ''),
                'result': report.get('result', ''),
                'status': report.get('status', 'Pending'),
                'date': report.get('date', datetime.now()).isoformat(),
                'confidence': report.get('confidence', 0),
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
            'date': report.get('date', datetime.now()).isoformat(),
            'confidence': report.get('confidence', 0),
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
        total_scans = mongo.db.reports.count_documents({})
        phishing_count = mongo.db.reports.count_documents({'result': 'Phishing'})
        safe_count = mongo.db.reports.count_documents({'result': 'Safe'})
        
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
