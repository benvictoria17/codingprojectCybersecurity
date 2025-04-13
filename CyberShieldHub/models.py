from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class PasswordHistory(db.Model):
    """Model for storing generated passwords"""
    id = db.Column(db.Integer, primary_key=True)
    password_hash = db.Column(db.String(64))  # Store only the hash, not the actual password
    length = db.Column(db.Integer)
    strength = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<PasswordHistory id={self.id}, strength={self.strength}>'

class LeakCheck(db.Model):
    """Model for storing leak check attempts"""
    id = db.Column(db.Integer, primary_key=True)
    email_hash = db.Column(db.String(64))  # Store hash of email, not the actual email
    breach_count = db.Column(db.Integer)
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<LeakCheck id={self.id}, breach_count={self.breach_count}>'

class PhishingCheck(db.Model):
    """Model for storing phishing check attempts"""
    id = db.Column(db.Integer, primary_key=True)
    content_hash = db.Column(db.String(64))  # Store hash of content, not the actual content
    is_phishing = db.Column(db.Boolean)
    confidence = db.Column(db.Float)
    checked_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<PhishingCheck id={self.id}, is_phishing={self.is_phishing}>'

class ToolUsage(db.Model):
    """Model for tracking tool usage"""
    id = db.Column(db.Integer, primary_key=True)
    tool_name = db.Column(db.String(50))
    action = db.Column(db.String(50))
    used_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ToolUsage id={self.id}, tool={self.tool_name}, action={self.action}>'