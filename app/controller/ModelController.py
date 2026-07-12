"""
Model Controller - Mengelola database dataset, melatih ulang model XGBoost,
dan memperbarui model klasifikasi phishing aktif.
"""

from flask import request, jsonify
from app import mongo, response
from bson import ObjectId
from datetime import datetime
import os
import shutil
import numpy as np
import tldextract
import joblib
from threading import Thread
from flask_jwt_extended import jwt_required

# Global state untuk progress training dan seeding
training_state = {
    "is_training": False,
    "is_seeding": False,
    "seed_progress": "Belum ada proses berjalan.",
    "temp_metrics": None
}

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

def ensure_versioned_file(version):
    model_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
        'model_ekstensi'
    )
    versioned_path = os.path.join(model_dir, f'hybrid_xgboost_phishing_{version}.joblib')
    live_path = os.path.join(model_dir, 'hybrid_xgboost_phishing.joblib')
    
    if not os.path.exists(versioned_path) and os.path.exists(live_path):
        try:
            shutil.copy(live_path, versioned_path)
            print(f"[ModelController] Archived current active model as {version}")
        except Exception as e:
            print(f"[ModelController] Failed to archive model: {e}")

def init_model_metadata_if_empty():
    try:
        existing = mongo.db.model_metadata.find_one({"is_active": True})
        if not existing:
            # Seed default metadata matching initial v1.0.0 model
            default_metadata = {
                "version": "v1.0.0",
                "last_trained": datetime(2026, 2, 15),
                "accuracy": 0.8584,
                "precision": 0.8196,
                "recall": 0.6442,
                "f1_score": 0.7214,
                "dataset_size": 549346,
                "is_active": True
            }
            mongo.db.model_metadata.insert_one(default_metadata)
            print("[ModelController] Default model metadata initialized in DB")
            
        active = mongo.db.model_metadata.find_one({"is_active": True})
        if active:
            ensure_versioned_file(active.get("version", "v1.0.0"))
    except Exception as e:
        print(f"[ModelController] Error initializing model metadata: {e}")

def init_extension_config_if_empty():
    try:
        existing = mongo.db.extension_config.find_one()
        if not existing:
            default_config = {
                "maintenance_mode": False,
                "maintenance_message": "Sistem sedang dalam pemeliharaan rutin. Kami akan segera kembali online.",
                "app_name": "Secure Link Guardian",
                "app_logo_url": "",
                "announcement": ""
            }
            mongo.db.extension_config.insert_one(default_config)
            print("[ModelController] Default extension config initialized in DB")
    except Exception as e:
        print(f"[ModelController] Error initializing extension config: {e}")

def bg_seed_dataset():
    global training_state
    try:
        training_state["is_seeding"] = True
        training_state["seed_progress"] = "Mengunduh dataset dari Kaggle (via kagglehub)..."
        
        # Bersihkan koleksi lama dan buat indeks unik terlebih dahulu
        try:
            mongo.db.dataset_links.delete_many({})
            mongo.db.dataset_links.drop_indexes()
            mongo.db.dataset_links.create_index("url", unique=True)
        except Exception as err:
            print(f"[ModelController] Warning clearing collection or creating index: {err}")
            
        import kagglehub
        import pandas as pd
        
        path = kagglehub.dataset_download("taruntiwarihp/phishing-site-urls")
        csv_path = os.path.join(path, "phishing_site_urls.csv")
        
        training_state["seed_progress"] = "Membaca file dataset (CSV)..."
        df_raw = pd.read_csv(csv_path, engine="python", header=0)
        
        # Bersihkan URL (strip space) dan buang duplikat di tingkat pandas
        df_raw["URL"] = df_raw["URL"].astype(str).str.strip()
        df_raw = df_raw.drop_duplicates(subset=["URL"])
        
        # Bersihkan label
        df_raw["Label"] = df_raw["Label"].str.replace(r"[^a-zA-Z]", "", regex=True).str.strip().str.lower()
        
        df_bad = df_raw[df_raw["Label"] == "bad"]
        df_good = df_raw[df_raw["Label"] == "good"]
        
        # Ambil sampel seimbang untuk mencegah storage overhead (masing-masing 150k URL)
        num_samples = min(len(df_bad), 150000)
        df_bad_sample = df_bad.sample(n=num_samples, random_state=42)
        df_good_sample = df_good.sample(n=num_samples, random_state=42)
        
        df_balanced = pd.concat([df_bad_sample, df_good_sample]).sample(frac=1, random_state=42) # Shuffle
        
        total_to_insert = len(df_balanced)
        training_state["seed_progress"] = f"Mulai memasukkan {total_to_insert} URL ke MongoDB..."
        
        # Lakukan insert_many dalam bentuk chunk
        chunk_size = 5000
        records = []
        
        for idx, row in df_balanced.iterrows():
            records.append({
                "url": str(row["URL"]),
                "label": 1 if row["Label"] == "bad" else 0,
                "source": "kaggle",
                "date_added": datetime.utcnow()
            })
            
            if len(records) == chunk_size:
                try:
                    mongo.db.dataset_links.insert_many(records, ordered=False)
                except Exception:
                    pass # Abaikan duplikat jika ada
                records = []
                current_count = mongo.db.dataset_links.count_documents({})
                training_state["seed_progress"] = f"Telah mengimpor {current_count}/{total_to_insert} URL..."
                
        if records:
            try:
                mongo.db.dataset_links.insert_many(records, ordered=False)
            except Exception:
                pass
            
        final_count = mongo.db.dataset_links.count_documents({})
        training_state["seed_progress"] = f"Selesai! Berhasil mengimpor {final_count} URL ke database."
    except Exception as e:
        print(f"[ModelController] Error during seeding: {e}")
        training_state["seed_progress"] = f"Gagal seeding: {str(e)}"
    finally:
        training_state["is_seeding"] = False

def bg_retrain_model(app, user_name, user_email):
    global training_state
    try:
        training_state["is_training"] = True
        training_state["temp_metrics"] = None
        
        # Ambil semua data dari dataset_links
        cursor = mongo.db.dataset_links.find({})
        df_list = list(cursor)
        
        if len(df_list) < 100:
            raise Exception("Jumlah data di database terlalu sedikit untuk pelatihan model (minimal 100 data).")
            
        import pandas as pd
        df = pd.DataFrame(df_list)
        
        urls = df["url"].astype(str).tolist()
        labels = df["label"].astype(int).tolist()
        
        # Ekstraksi fitur leksikal
        X = []
        for url in urls:
            X.append(extract_features(url))
            
        from sklearn.model_selection import train_test_split
        from xgboost import XGBClassifier
        from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
        
        X = np.array(X)
        y = np.array(labels)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=0.2,
            random_state=42,
            stratify=y
        )
        
        model = XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            objective="binary:logistic",
            eval_metric="logloss",
            random_state=42
        )
        
        model.fit(X_train, y_train)
        
        # Evaluasi
        y_pred = model.predict(X_test)
        
        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, zero_division=0))
        rec = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))
        
        # Simpan sementara
        temp_model_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
            'model_ekstensi', 
            'hybrid_xgboost_phishing_temp.joblib'
        )
        
        joblib.dump(model, temp_model_path)
        
        training_state["temp_metrics"] = {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "dataset_size": len(df),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Kirim email pemberitahuan ke semua admin secara asinkron
        with app.app_context():
            ModelController.send_training_complete_email(acc, prec, rec, f1, len(df), user_name, user_email)
    except Exception as e:
        print(f"[ModelController] Error during retraining: {e}")
        training_state["temp_metrics"] = {
            "error": str(e)
        }
    finally:
        training_state["is_training"] = False

# Class Controller Flask
class ModelController:
    
    @staticmethod
    def get_status():
        init_model_metadata_if_empty()
        
        # Dapatkan model aktif
        active_model = mongo.db.model_metadata.find_one({"is_active": True})
        if active_model:
            active_model["_id"] = str(active_model["_id"])
            if isinstance(active_model.get("last_trained"), datetime):
                active_model["last_trained"] = active_model["last_trained"].isoformat()
        else:
            active_model = {
                "version": "v1.0.0",
                "last_trained": datetime(2026, 2, 15).isoformat(),
                "accuracy": 0.8584,
                "precision": 0.8196,
                "recall": 0.6442,
                "f1_score": 0.7214,
                "dataset_size": 549346,
                "is_active": True
            }
            
        # Dapatkan daftar semua model untuk admin switch
        models_list = []
        try:
            all_models = list(mongo.db.model_metadata.find().sort('last_trained', -1))
            for m in all_models:
                m_id = str(m["_id"])
                last_trained = m.get("last_trained")
                if isinstance(last_trained, datetime):
                    last_trained = last_trained.isoformat()
                models_list.append({
                    "id": m_id,
                    "version": m.get("version"),
                    "last_trained": last_trained,
                    "accuracy": m.get("accuracy"),
                    "precision": m.get("precision"),
                    "recall": m.get("recall"),
                    "f1_score": m.get("f1_score"),
                    "dataset_size": m.get("dataset_size"),
                    "is_active": m.get("is_active", False)
                })
        except Exception as err_m:
            print(f"[ModelController] Error loading all models: {err_m}")
            
        # Hitung statistik dataset
        try:
            total_dataset = mongo.db.dataset_links.count_documents({})
            phishing_count = mongo.db.dataset_links.count_documents({"label": 1})
            safe_count = mongo.db.dataset_links.count_documents({"label": 0})
            admin_blacklist_count = mongo.db.dataset_links.count_documents({"source": "admin_blacklist"})
        except Exception:
            total_dataset = 0
            phishing_count = 0
            safe_count = 0
            admin_blacklist_count = 0
            
        status_data = {
            "active_model": active_model,
            "models": models_list,
            "dataset": {
                "total": total_dataset,
                "phishing": phishing_count,
                "safe": safe_count,
                "admin_blacklist": admin_blacklist_count,
                "is_seeded": total_dataset > 0
            },
            "is_training": training_state["is_training"],
            "is_seeding": training_state["is_seeding"],
            "seed_progress": training_state["seed_progress"],
            "temp_metrics": training_state["temp_metrics"]
        }
        
        return response.success(status_data, "Status model berhasil dimuat.")

    @staticmethod
    def import_dataset():
        if training_state["is_seeding"]:
            return response.badRequest([], "Proses seeding dataset sedang berjalan.")
            
        # Jalankan di background thread
        thread = Thread(target=bg_seed_dataset)
        thread.start()
        
        return response.success({}, "Proses impor dataset telah dimulai di background.")

    @staticmethod
    def retrain():
        if training_state["is_training"]:
            return response.badRequest([], "Proses pelatihan ulang model sedang berjalan.")
            
        # Ambil detail user pembuat aksi dari JWT
        try:
            from flask_jwt_extended import get_jwt_identity
            user_id = get_jwt_identity()
            user_data = mongo.db.user.find_one({"_id": ObjectId(user_id)})
            user_name = user_data.get("nama", "Admin") if user_data else "Admin"
            user_email = user_data.get("email", "admin@email.com") if user_data else "admin@email.com"
        except Exception as e:
            print(f"[ModelController] JWT user resolution failed for retrain: {e}")
            user_name, user_email = "Admin System", "system@email.com"
            
        # Dapatkan Flask app object yang sebenarnya untuk dioper ke thread
        from flask import current_app
        app = current_app._get_current_object()
        
        # Jalankan di background thread
        thread = Thread(target=bg_retrain_model, args=[app, user_name, user_email])
        thread.start()
        
        return response.success({}, "Proses pelatihan ulang model telah dimulai di background.")

    @staticmethod
    def apply_model():
        temp_model_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
            'model_ekstensi', 
            'hybrid_xgboost_phishing_temp.joblib'
        )
        active_model_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
            'model_ekstensi', 
            'hybrid_xgboost_phishing.joblib'
        )
        
        if not os.path.exists(temp_model_path) or not training_state["temp_metrics"]:
            return response.badRequest([], "Tidak ada model baru yang siap diterapkan.")
            
        try:
            # Cari version aktif saat ini
            active_model = mongo.db.model_metadata.find_one({"is_active": True})
            if active_model:
                curr_version = active_model.get("version", "v1.0.0")
                # Pastikan model aktif lama diarsipkan
                ensure_versioned_file(curr_version)
                
                # Increment patch version (e.g. v1.0.0 -> v1.0.1)
                try:
                    parts = curr_version.replace("v", "").split(".")
                    major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
                    new_version = f"v{major}.{minor}.{patch + 1}"
                except Exception:
                    new_version = "v1.0.1"
            else:
                new_version = "v1.0.1"
                
            metrics = training_state["temp_metrics"]
            
            # Simpan model baru sebagai file ter-versi
            model_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                'model_ekstensi'
            )
            versioned_model_path = os.path.join(model_dir, f'hybrid_xgboost_phishing_{new_version}.joblib')
            shutil.copy(temp_model_path, versioned_model_path)
            
            # Salin juga ke file aktif utama
            shutil.copy(temp_model_path, active_model_path)
            
            new_metadata = {
                "version": new_version,
                "last_trained": datetime.utcnow(),
                "accuracy": metrics["accuracy"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
                "f1_score": metrics["f1_score"],
                "dataset_size": metrics["dataset_size"],
                "is_active": True
            }
            
            # Set all other model metadata to inactive
            mongo.db.model_metadata.update_many({}, {"$set": {"is_active": False}})
            # Insert new active metadata
            mongo.db.model_metadata.insert_one(new_metadata)
            
            # Reload model di memori ReportController
            from app.controller.ReportController import reload_model
            reload_model()
            
            # Hapus temp file dan reset state metrics
            if os.path.exists(temp_model_path):
                os.remove(temp_model_path)
            training_state["temp_metrics"] = None
            
            # Ambil detail user pembuat aksi dari JWT
            try:
                from flask_jwt_extended import get_jwt_identity
                user_id = get_jwt_identity()
                user_data = mongo.db.user.find_one({"_id": ObjectId(user_id)})
                user_name = user_data.get("nama", "Admin") if user_data else "Admin"
                user_email = user_data.get("email", "admin@email.com") if user_data else "admin@email.com"
            except Exception as e:
                print(f"[ModelController] JWT user resolution failed: {e}")
                user_name, user_email = "Admin System", "system@email.com"
                
            # Kirim notifikasi email secara aman
            ModelController.send_model_update_email(new_version, metrics, user_name, user_email)
            
            return response.success(new_metadata, "Model baru berhasil diterapkan sistem.")
        except Exception as e:
            print(f"[ModelController] Error applying model: {e}")
            return response.error([], f"Gagal menerapkan model baru: {str(e)}")

    @staticmethod
    def activate_model():
        """
        Aktifkan versi model tertentu yang sudah pernah disimpan
        POST /model/activate
        """
        try:
            data = request.get_json()
            if not data or 'version' not in data:
                return response.badRequest([], "Parameter version wajib diisi.")
                
            version = data.get('version').strip()
            
            # Cari model di database
            target_model = mongo.db.model_metadata.find_one({"version": version})
            if not target_model:
                return response.notFound([], f"Model dengan versi {version} tidak ditemukan di database.")
                
            model_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                'model_ekstensi'
            )
            versioned_path = os.path.join(model_dir, f'hybrid_xgboost_phishing_{version}.joblib')
            live_path = os.path.join(model_dir, 'hybrid_xgboost_phishing.joblib')
            
            # Jika file versi belum ada, tapi ada model aktif utama, buat salinannya sebagai arsip
            if not os.path.exists(versioned_path):
                if os.path.exists(live_path):
                    shutil.copy(live_path, versioned_path)
                else:
                    return response.error([], f"File model untuk versi {version} tidak ditemukan di server.")
            
            # Salin model versi ke model utama yang aktif
            shutil.copy(versioned_path, live_path)
            
            # Update database
            mongo.db.model_metadata.update_many({}, {"$set": {"is_active": False}})
            mongo.db.model_metadata.update_one({"version": version}, {"$set": {"is_active": True}})
            
            # Reload model di memori ReportController
            from app.controller.ReportController import reload_model
            reload_model()
            
            # Ambil detail user pembuat aksi dari JWT
            try:
                from flask_jwt_extended import get_jwt_identity
                user_id = get_jwt_identity()
                user_data = mongo.db.user.find_one({"_id": ObjectId(user_id)})
                user_name = user_data.get("nama", "Admin") if user_data else "Admin"
                user_email = user_data.get("email", "admin@email.com") if user_data else "admin@email.com"
            except Exception as e:
                print(f"[ModelController] JWT user resolution failed: {e}")
                user_name, user_email = "Admin System", "system@email.com"
                
            # Metrik untuk notifikasi email
            metrics = {
                "accuracy": target_model.get("accuracy", 0),
                "precision": target_model.get("precision", 0),
                "recall": target_model.get("recall", 0),
                "f1_score": target_model.get("f1_score", 0),
                "dataset_size": target_model.get("dataset_size", 0)
            }
            # Kirim notifikasi email secara aman
            ModelController.send_model_update_email(version, metrics, user_name, user_email)
            
            # Dapatkan model terupdate untuk dikembalikan
            updated_model = mongo.db.model_metadata.find_one({"version": version})
            updated_model["_id"] = str(updated_model["_id"])
            if isinstance(updated_model.get("last_trained"), datetime):
                updated_model["last_trained"] = updated_model["last_trained"].isoformat()
                
            return response.success(updated_model, f"Model versi {version} berhasil diaktifkan.")
        except Exception as e:
            print(f"[ModelController] Error activating model: {e}")
            return response.error([], f"Gagal mengaktifkan model: {str(e)}")

    @staticmethod
    def discard_model():
        temp_model_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
            'model_ekstensi', 
            'hybrid_xgboost_phishing_temp.joblib'
        )
        
        try:
            if os.path.exists(temp_model_path):
                os.remove(temp_model_path)
            training_state["temp_metrics"] = None
            return response.success({}, "Pembaruan model dibatalkan dan dibuang.")
        except Exception as e:
            return response.error([], f"Gagal membatalkan pembaruan: {str(e)}")

    @staticmethod
    def get_dataset():
        """
        Dapatkan data set yang telah dilatih dengan filter dan pagination
        GET /model/dataset
        """
        try:
            page = request.args.get('page', 1, type=int)
            limit = request.args.get('limit', 10, type=int)
            search = request.args.get('search', '').strip()
            label = request.args.get('label', -1, type=int)
            source = request.args.get('source', 'all').strip()
            
            skip = (page - 1) * limit
            
            query = {}
            if search:
                query["url"] = {"$regex": search, "$options": "i"}
            if label != -1:
                query["label"] = label
            if source != "all":
                query["source"] = source
                
            dataset_cursor = mongo.db.dataset_links.find(query).sort('date_added', -1).skip(skip).limit(limit)
            dataset = list(dataset_cursor)
            total = mongo.db.dataset_links.count_documents(query)
            
            result = []
            for d in dataset:
                result.append({
                    "id": str(d.get("_id")),
                    "url": d.get("url", ""),
                    "label": int(d.get("label", 0)),
                    "source": d.get("source", "kaggle"),
                    "date_added": d.get("date_added", datetime.utcnow()).isoformat() if isinstance(d.get("date_added"), datetime) else str(d.get("date_added", ""))
                })
                
            return response.success({
                'dataset': result,
                'total': total,
                'page': page,
                'limit': limit,
                'pages': (total + limit - 1) // limit if total > 0 else 0
            }, "Dataset berhasil diambil")
        except Exception as e:
            print(f"[ModelController] Error getting dataset: {e}")
            return response.error([], f"Gagal mengambil dataset: {str(e)}")

    @staticmethod
    def get_extension_config():
        """
        Dapatkan konfigurasi ekstensi
        GET /extension/config
        """
        try:
            init_extension_config_if_empty()
            config = mongo.db.extension_config.find_one()
            
            result = {
                "maintenance_mode": config.get("maintenance_mode", False),
                "maintenance_message": config.get("maintenance_message", "Sistem sedang dalam pemeliharaan."),
                "app_name": config.get("app_name", "Secure Link Guardian"),
                "app_logo_url": config.get("app_logo_url", ""),
                "announcement": config.get("announcement", "")
            }
            return response.success(result, "Konfigurasi ekstensi berhasil diambil.")
        except Exception as e:
            print(f"[ModelController] Error getting extension config: {e}")
            return response.error([], f"Gagal mengambil konfigurasi ekstensi: {str(e)}")

    @staticmethod
    def update_extension_config():
        """
        Perbarui konfigurasi ekstensi
        POST /admin/extension/config
        """
        try:
            init_extension_config_if_empty()
            data = request.get_json()
            
            if not data:
                return response.badRequest([], "Data konfigurasi wajib dikirimkan.")
                
            update_data = {}
            if "maintenance_mode" in data:
                update_data["maintenance_mode"] = bool(data.get("maintenance_mode"))
            if "maintenance_message" in data:
                update_data["maintenance_message"] = str(data.get("maintenance_message")).strip()
            if "app_name" in data:
                update_data["app_name"] = str(data.get("app_name")).strip()
            if "app_logo_url" in data:
                update_data["app_logo_url"] = str(data.get("app_logo_url")).strip()
            if "announcement" in data:
                update_data["announcement"] = str(data.get("announcement")).strip()
                
            if not update_data:
                return response.badRequest([], "Tidak ada kolom konfigurasi yang diperbarui.")
                
            mongo.db.extension_config.update_many({}, {"$set": update_data})
            
            # Kembalikan config terupdate
            config = mongo.db.extension_config.find_one()
            result = {
                "maintenance_mode": config.get("maintenance_mode", False),
                "maintenance_message": config.get("maintenance_message", "Sistem sedang dalam pemeliharaan."),
                "app_name": config.get("app_name", "Secure Link Guardian"),
                "app_logo_url": config.get("app_logo_url", ""),
                "announcement": config.get("announcement", "")
            }
            return response.success(result, "Konfigurasi ekstensi berhasil diperbarui.")
        except Exception as e:
            print(f"[ModelController] Error updating extension config: {e}")
            return response.error([], f"Gagal memperbarui konfigurasi ekstensi: {str(e)}")

    @staticmethod
    def upload_extension_logo():
        """
        Upload logo kustom untuk ekstensi
        POST /admin/extension/upload-logo
        """
        try:
            init_extension_config_if_empty()
            
            file = request.files.get('file')
            if not file or file.filename == '':
                return response.badRequest([], "File tidak ditemukan atau kosong")
                
            from werkzeug.utils import secure_filename
            import os
            import time
            from flask import current_app
            
            filename = secure_filename(file.filename)
            ext = os.path.splitext(filename)[1].lower()
            
            if ext not in ['.png', '.jpg', '.jpeg', '.gif', '.svg']:
                return response.badRequest([], "Format file tidak didukung. Harap unggah berkas gambar (PNG, JPG, JPEG, GIF, SVG).")
                
            new_filename = f"extension_logo{ext}"
            upload_path = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_path, exist_ok=True)
            save_path = os.path.join(upload_path, new_filename)
            
            # Hapus file logo lama dengan ekstensi lain jika ada
            for existing_ext in ['.png', '.jpg', '.jpeg', '.gif', '.svg']:
                old_file = os.path.join(upload_path, f"extension_logo{existing_ext}")
                if os.path.exists(old_file) and existing_ext != ext:
                    try:
                        os.remove(old_file)
                    except Exception:
                        pass
                        
            file.save(save_path)
            print(f"[ModelController] Extension logo saved at: {save_path}")
            
            # Base URL for download link
            base_url = request.host_url
            if "localhost" not in request.host_url and "127.0.0.1" not in request.host_url:
                base_url = base_url.replace("http://", "https://")
            if "api.atlass.my.id" in request.host_url:
                base_url = "https://api.atlass.my.id/"
                
            # Buat URL lengkap dengan cache-buster
            logo_url = f"{base_url}uploads/{new_filename}?t={int(time.time())}"
            
            # Update database
            mongo.db.extension_config.update_many({}, {"$set": {"app_logo_url": logo_url}})
            
            config = mongo.db.extension_config.find_one()
            result = {
                "maintenance_mode": config.get("maintenance_mode", False),
                "maintenance_message": config.get("maintenance_message", "Sistem sedang dalam pemeliharaan."),
                "app_name": config.get("app_name", "Secure Link Guardian"),
                "app_logo_url": config.get("app_logo_url", ""),
                "announcement": config.get("announcement", "")
            }
            return response.success(result, "Logo ekstensi berhasil diperbarui.")
        except Exception as e:
            print(f"[ModelController] Error uploading extension logo: {e}")
            return response.error([], f"Gagal mengunggah logo: {str(e)}")

    @staticmethod
    def get_active_version():
        try:
            active = mongo.db.extension_versions.find_one({"is_active": True})
            if not active:
                # Fallback to static if no version is active
                return response.success({
                    "version": "1.0",
                    "url": "https://api.atlass.my.id/uploads/smartxgboost.zip",
                    "filename": "smartxgboost.zip",
                    "is_active": True
                }, "Active version found (default fallback).")
            
            active["_id"] = str(active["_id"])
            if "uploaded_at" in active:
                active["uploaded_at"] = active["uploaded_at"].isoformat()
            return response.success(active, "Active version retrieved successfully.")
        except Exception as e:
            return response.error([], f"Gagal mengambil versi aktif: {str(e)}")

    @staticmethod
    def get_all_versions():
        try:
            versions = list(mongo.db.extension_versions.find().sort("uploaded_at", -1))
            for v in versions:
                v["_id"] = str(v["_id"])
                if "uploaded_at" in v:
                    v["uploaded_at"] = v["uploaded_at"].isoformat()
            return response.success(versions, "Semua versi berhasil diambil.")
        except Exception as e:
            return response.error([], f"Gagal mengambil daftar versi: {str(e)}")

    @staticmethod
    def upload_version():
        try:
            from werkzeug.utils import secure_filename
            from flask import current_app
            
            version_num = request.form.get("version", "").strip()
            description = request.form.get("description", "").strip()
            
            if not version_num:
                return response.badRequest([], "Nomor versi wajib diisi.")
                
            file = request.files.get("file")
            if not file or file.filename == "":
                return response.badRequest([], "Berkas zip wajib diunggah.")
                
            filename = secure_filename(file.filename)
            ext = os.path.splitext(filename)[1].lower()
            if ext != ".zip":
                return response.badRequest([], "Format file tidak didukung. Harap unggah berkas .zip.")
                
            # Create a unique filename for the zip to avoid overwrite
            new_filename = f"phishing_guard_v{version_num}_{int(datetime.utcnow().timestamp())}.zip"
            upload_path = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_path, exist_ok=True)
            save_path = os.path.join(upload_path, new_filename)
            
            file.save(save_path)
            
            # Base URL for download link
            base_url = request.host_url
            if "localhost" not in request.host_url and "127.0.0.1" not in request.host_url:
                base_url = base_url.replace("http://", "https://")
            if "api.atlass.my.id" in request.host_url:
                base_url = "https://api.atlass.my.id/"
            
            url = f"{base_url}uploads/{new_filename}"
            
            # Insert into database
            version_doc = {
                "version": version_num,
                "description": description,
                "filename": new_filename,
                "url": url,
                "uploaded_at": datetime.utcnow(),
                "is_active": False
            }
            
            # If there are no other versions, make this one active by default
            existing_count = mongo.db.extension_versions.count_documents({})
            if existing_count == 0:
                version_doc["is_active"] = True
                
            mongo.db.extension_versions.insert_one(version_doc)
            
            return response.success(None, "Versi baru berhasil diunggah.")
        except Exception as e:
            return response.error([], f"Gagal mengunggah versi: {str(e)}")

    @staticmethod
    def activate_version():
        try:
            data = request.get_json()
            version_id = data.get("version_id")
            if not version_id:
                return response.badRequest([], "ID versi wajib disertakan.")
                
            # Set all to inactive
            mongo.db.extension_versions.update_many({}, {"$set": {"is_active": False}})
            
            # Set target to active
            res = mongo.db.extension_versions.update_one(
                {"_id": ObjectId(version_id)},
                {"$set": {"is_active": True}}
            )
            
            if res.matched_count == 0:
                return response.badRequest([], "Versi tidak ditemukan.")
                
            return response.success(None, "Versi berhasil diaktifkan.")
        except Exception as e:
            return response.error([], f"Gagal mengaktifkan versi: {str(e)}")

    @staticmethod
    def delete_version(version_id):
        try:
            version = mongo.db.extension_versions.find_one({"_id": ObjectId(version_id)})
            if not version:
                return response.badRequest([], "Versi tidak ditemukan.")
                
            # Delete physical file
            filename = version.get("filename")
            if filename:
                from flask import current_app
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(file_path):
                    try:
                        os.remove(file_path)
                    except Exception as e:
                        print(f"Error removing file {file_path}: {e}")
                        
            # Delete from DB
            mongo.db.extension_versions.delete_one({"_id": ObjectId(version_id)})
            
            # If the deleted version was active, make the latest remaining one active
            if version.get("is_active"):
                latest = mongo.db.extension_versions.find_one(sort=[("uploaded_at", -1)])
                if latest:
                    mongo.db.extension_versions.update_one(
                        {"_id": latest["_id"]},
                        {"$set": {"is_active": True}}
                    )
                    
            return response.success(None, "Versi berhasil dihapus.")
        except Exception as e:
            return response.error([], f"Gagal menghapus versi: {str(e)}")

    @staticmethod
    def send_model_update_email(version, metrics, user_name, user_email):
        """
        Kirim email notifikasi perubahan model kepada seluruh admin secara asinkron
        """
        try:
            from app import mail
            from flask_mail import Message
            
            # Cari semua admin
            admins = list(mongo.db.user.find({"$or": [{"role": "1"}, {"role": "admin"}]}))
            admin_emails = [a["email"] for a in admins if a.get("email")]
            
            if not admin_emails:
                print("[ModelController] No admins found to send email.")
                return
                
            subject = f"[Notification] Pembaruan Model Klasifikasi Phishing - {version}"
            
            body = f"""Halo Admin,

Pemberitahuan bahwa model klasifikasi phishing telah diperbarui di sistem.

Detail Perubahan:
- Dilakukan oleh: {user_name} ({user_email})
- Versi Model Baru: {version}
- Metrik Evaluasi:
  * Akurasi: {metrics.get("accuracy", 0) * 100:.2f}%
  * F1-Score: {metrics.get("f1_score", 0) * 100:.2f}%
  * Presisi: {metrics.get("precision", 0) * 100:.2f}%
  * Recall: {metrics.get("recall", 0) * 100:.2f}%
- Ukuran Dataset Latih: {metrics.get("dataset_size", 0):,} URL
- Waktu Perubahan: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

Silakan tinjau status model ter-update di Dashboard Admin.

Terima kasih,
Sistem Secure Link Guardian
"""
            
            msg = Message(
                subject=subject,
                recipients=admin_emails,
                body=body
            )
            
            # Kirim secara asinkron agar tidak memblokir HTTP response
            from threading import Thread
            from flask import current_app
            app = current_app._get_current_object()
            
            def send_async_email(app, msg):
                with app.app_context():
                    try:
                        mail.send(msg)
                        print("[ModelController] Model update email sent successfully.")
                    except Exception as e:
                        print(f"[ModelController] Failed to send model update email: {e}")
                        
            thr = Thread(target=send_async_email, args=[app, msg])
            thr.start()
            print("[ModelController] Spawning background thread to send model update email.")
        except Exception as e:
            print(f"[ModelController] Failed to trigger model update email: {e}")

    @staticmethod
    def send_training_complete_email(accuracy, precision, recall, f1_score, dataset_size, user_name, user_email):
        """
        Kirim email notifikasi bahwa pelatihan model (retrain) selesai dilaksanakan di background
        """
        try:
            from app import mail
            from flask_mail import Message
            
            admins = list(mongo.db.user.find({"$or": [{"role": "1"}, {"role": "admin"}]}))
            admin_emails = [a["email"] for a in admins if a.get("email")]
            
            if not admin_emails:
                print("[ModelController] No admins found to send email.")
                return
                
            subject = "[Notification] Pelatihan Model Klasifikasi Phishing Selesai"
            
            body = f"""Halo Admin,

Pemberitahuan bahwa proses pelatihan ulang model (Retrain Model) telah SELESAI dilaksanakan di background.

Detail Pelatihan:
- Diinisiasi oleh: {user_name} ({user_email})
- Hasil Metrik Model Baru:
  * Akurasi: {accuracy * 100:.2f}%
  * F1-Score: {f1_score * 100:.2f}%
  * Presisi: {precision * 100:.2f}%
  * Recall: {recall * 100:.2f}%
- Ukuran Dataset Latih: {dataset_size:,} URL
- Waktu Selesai: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}

Model baru ini sekarang berstatus sebagai "Kandidat". Silakan masuk ke Dashboard Admin di tab Model Info dan klik "Terapkan Model" untuk mengaktifkan model baru ini ke seluruh sistem.

Terima kasih,
Sistem Secure Link Guardian
"""
            
            msg = Message(
                subject=subject,
                recipients=admin_emails,
                body=body
            )
            
            # Kirim secara asinkron
            from threading import Thread
            from flask import current_app
            app = current_app._get_current_object()
            
            def send_async_email(app, msg):
                with app.app_context():
                    try:
                        mail.send(msg)
                        print("[ModelController] Training complete email sent successfully.")
                    except Exception as e:
                        print(f"[ModelController] Failed to send training complete email: {e}")
                        
            thr = Thread(target=send_async_email, args=[app, msg])
            thr.start()
            print("[ModelController] Spawning background thread to send training complete email.")
        except Exception as e:
            print(f"[ModelController] Failed to trigger training complete email: {e}")
