from flasgger import Swagger
from flask import Flask, redirect, url_for, render_template
from flask_login import login_required

from app.celery_app import celery, init_celery
from app.config import Config
from app.extensions import db, migrate, login_manager, limiter

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Инициализация расширений
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    limiter.init_app(app)

    # Инициализируем Celery контекстом созданного приложения
    init_celery(app)

    swagger = Swagger(app)

    # Настройка login_manager
    login_manager.login_view = 'auth.login'  # resolves to /admin/auth/login
    login_manager.login_message = 'Пожалуйста, войдите для доступа к этой странице.'

    # Регистрация blueprints
    from app.auth import bp as auth_bp
    from app.servers import bp as servers_bp
    from app.protocols import bp as protocols_bp
    from app.clients import bp as clients_bp
    from app.haproxy import bp as haproxy_bp
    from app.groups import bp as groups_bp
    from app.api import bp as api_bp
    from app.main import bp as main_bp
    from app.portal import bp as portal_bp

    # Admin blueprints — все под /admin
    app.register_blueprint(auth_bp, url_prefix='/admin/auth')
    app.register_blueprint(servers_bp, url_prefix='/admin/servers')
    app.register_blueprint(protocols_bp, url_prefix='/admin/servers/<int:server_id>/protocols')
    app.register_blueprint(clients_bp, url_prefix='/admin/clients')
    app.register_blueprint(haproxy_bp, url_prefix='/admin/haproxy')
    app.register_blueprint(groups_bp, url_prefix='/admin/groups')
    app.register_blueprint(main_bp, url_prefix='/admin')

    # API остаётся без /admin — используется в JS admin-шаблонов
    app.register_blueprint(api_bp)

    # Портал — корневой URL
    app.register_blueprint(portal_bp, url_prefix='/')

    @app.route('/admin/')
    @app.route('/admin')
    @login_required
    def index():
        return render_template('index.html')

    return app