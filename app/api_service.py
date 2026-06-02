from flask import request
from app import app, response, mongo  # Pastikan mongo sudah di-import dari app
import functools

def require_api_key(func):
    @functools.wraps(func)
    def decorated(*args, **kwargs):
        key = request.headers.get('x-api-key')

        if not key:
            return response.error([], "API key diperlukan", 401)

        # Cari key di MongoDB
        key_data = mongo.db.user.find_one({'api_key': key})
        if not key_data:
            return response.error([], "API key tidak valid", 403)

        return func(*args, **kwargs)
    return decorated
