from celery import Celery, Task
from celery.schedules import crontab
from app.config import Config

# Глобальная переменная для хранения экземпляра Flask, чтобы избежать конфликтов имен в классе Task
_flask_app = None

class FlaskTask(Task):
    """Базовый класс для всех задач Celery в проекте.
    Гарантирует, что каждая задача выполняется внутри контекста Flask-приложения.
    """
    
    def __call__(self, *args, **kwargs):
        global _flask_app
        if _flask_app is None:
            from app import create_app
            _flask_app = create_app()
        
        # Теперь точно используем контекст Flask приложения
        with _flask_app.app_context():
            return self.run(*args, **kwargs)

# Создаем экземпляр Celery с указанием нашего базового класса
celery = Celery(
    'rootcloud',
    broker=Config.broker_url,
    backend=Config.result_backend,
    include=['app.tasks'],
    task_cls=FlaskTask
)

celery.conf.beat_schedule = {
    'collect-stats-every-hour': {
        'task': 'app.tasks.collect_all_stats',
        'schedule': crontab(minute=0),
    },
    'check-limits-every-15-minutes': {
        'task': 'app.tasks.check_all_limits',
        'schedule': crontab(minute='*/15'),
    },
    'check-servers-status-every-5-minutes': {
        'task': 'app.tasks.check_all_servers_status',
        'schedule': crontab(minute='*/5'),
    },
    'cleanup-session-tokens-daily': {
        'task': 'app.tasks.cleanup_session_tokens',
        'schedule': crontab(hour=3, minute=0),
    },
}


def init_celery(app):
    """Сохранение ссылки на Flask приложение для контекста задач"""
    global _flask_app
    _flask_app = app
