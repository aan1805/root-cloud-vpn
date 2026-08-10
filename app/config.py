import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://amnezia:amnezia@localhost/amnezia_farm')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # По умолчанию SQLAlchemy держит соединения вечно и не проверяет их перед
    # выдачей из пула. Если соединение к postgres тихо умерло (перезапуск
    # контейнера, сброс conntrack), запрос повисает или падает до перезапуска web.
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 280,
        'pool_timeout': 30,
        'connect_args': {
            # Не даёт запросу висеть бесконечно на мёртвом TCP-соединении
            'connect_timeout': 10,
            'keepalives': 1,
            'keepalives_idle': 30,
            'keepalives_interval': 10,
            'keepalives_count': 3,
        },
    }

    # Настройки для Celery (новый формат Celery 5.x)
    broker_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    result_backend = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')

    # Ограничение попыток входа (flask-limiter)
    RATELIMIT_ENABLED = False
    RATELIMIT_DEFAULT = "100 per day;30 per hour;5 per minute"
    RATELIMIT_STORAGE_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/1')
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)