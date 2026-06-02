"""
Model untuk URL Scan Report
Menyimpan hasil scan URL untuk phishing detection
"""

from datetime import datetime

class Report:
    """
    Struktur data untuk Report
    - url: URL yang di-scan
    - result: 'Phishing' atau 'Safe'
    - status: 'Validated' atau 'Pending'
    - user_id: ID user yang melakukan scan
    - date: Tanggal scan
    - details: Detail tambahan dari scan
    """
    
    def __init__(self, url, result, user_id, status='Pending', details=None):
        self.url = url
        self.result = result
        self.user_id = user_id
        self.status = status
        self.date = datetime.now()
        self.details = details or {}
    
    def to_dict(self):
        return {
            'url': self.url,
            'result': self.result,
            'user_id': self.user_id,
            'status': self.status,
            'date': self.date.isoformat(),
            'details': self.details
        }
