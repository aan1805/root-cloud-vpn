from celery import Celery, Task
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
    broker=Config.CELERY_BROKER_URL,
    backend=Config.CELERY_RESULT_BACKEND,
    include=['app.tasks'],
    task_cls=FlaskTask
)

def init_celery(app):
    """Обновление конфига и сохранение ссылки на приложение"""
    global _flask_app
    _flask_app = app
    celery.conf.update(app.config)
