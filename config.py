import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Configuration class for SABTRACK application settings."""
    SECRET_KEY = os.getenv('SECRET_KEY', 'sabtrack-secret-key-2025')
    DATABASE = 'instance/sabtrack.db'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    
    # Email configuration
    EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS', 'sabtrack@barangaysabang.com')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
    SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
