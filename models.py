from datetime import datetime

class User(db.Model):
    # ... existing code ...
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # ... existing code ... 