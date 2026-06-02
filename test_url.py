import sys
import os
import joblib
import numpy as np
import tldextract
import json

# Path model baru
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'model_ekstensi', 'nlp_xgboost_phishing_pipeline.joblib')

if not os.path.exists(MODEL_PATH):
    print(f"ERROR: Model tidak ditemukan di {MODEL_PATH}")
    sys.exit(1)

# Load model
try:
    model = joblib.load(MODEL_PATH)
    print("✅ Model loaded successfully!")
except Exception as e:
    print(f"❌ Failed to load model: {e}")
    sys.exit(1)

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

def test_url(url):
    # Coba deteksi model tipe input apa
    prediction = None
    proba = None
    model_type = "Unknown"
    
    try:
        # Coba menggunakan raw URL string (untuk NLP Pipeline TfidfVectorizer + XGB)
        prediction = model.predict([url])[0]
        proba = model.predict_proba([url])[0]
        model_type = "NLP Pipeline (Raw URL String)"
    except Exception as e:
        # Jika gagal, coba gunakan manual lexical features
        print(f"⚠️ NLP prediction failed ({e}), trying fallback lexical features...")
        features = extract_features(url)
        X = np.array([features])
        prediction = model.predict(X)[0]
        proba = model.predict_proba(X)[0]
        model_type = "Tabular Model (Lexical Features)"
        
    features_list = extract_features(url)
    
    result = {
        "url": url,
        "model_type_used": model_type,
        "prediction_raw": int(prediction),
        "result": "Phishing" if prediction == 1 else "Safe",
        "confidence": float(max(proba)),
        "extracted_lexical_features": {
            "url_length": features_list[0],
            "dots_count": features_list[1],
            "dashes_count": features_list[2],
            "at_count": features_list[3],
            "question_count": features_list[4],
            "equals_count": features_list[5],
            "slash_count": features_list[6],
            "http_count": features_list[7],
            "is_https": features_list[8],
            "domain_length": features_list[9],
            "subdomain_length": features_list[10]
        }
    }
    return result

if __name__ == "__main__":
    print("--- Alat Uji Model Phishing Terbaru (JSON) ---")
    if len(sys.argv) > 1:
        # Jika ada argumen URL dari command line
        url_input = sys.argv[1]
        res = test_url(url_input)
        print(json.dumps(res, indent=4))
    else:
        # Input interaktif
        print("Masukkan URL yang ingin diuji:")
        url_input = input("> ").strip()
        if url_input:
            res = test_url(url_input)
            print("\nHasil Evaluasi (Format JSON):")
            print(json.dumps(res, indent=4))
        else:
            print("URL tidak boleh kosong!")
