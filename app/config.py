import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://amnezia:amnezia@localhost/amnezia_farm')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Настройки для Celery
    CELERY_BROKER_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

    # Ограничение попыток входа (flask-limiter)
    RATELIMIT_ENABLED = False
    RATELIMIT_DEFAULT = "100 per day;30 per hour;5 per minute"
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/1')
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)