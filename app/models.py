from app.extensions import db
from flask_login import UserMixin
from datetime import datetime
import bcrypt
from app.extensions import login_manager

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

class Admin(UserMixin, db.Model):
    __tablename__ = 'admins'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class ServerGroup(db.Model):
    __tablename__ = 'server_groups'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    servers = db.relationship('Server', backref='group', lazy=True)
    clients = db.relationship('Client', backref='group', lazy=True)

class Server(db.Model):
    __tablename__ = 'servers'

    id = db.Column(db.Integer, primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('server_groups.id'), nullable=True)
    name = db.Column(db.String(128), nullable=False)  # метка/имя сервера
    ip = db.Column(db.String(64), nullable=False)
    ssh_port = db.Column(db.Integer, default=22)
    ssh_username = db.Column(db.String(64), nullable=False)
    ssh_key_encrypted = db.Column(db.Text, nullable=True)  # зашифрованный приватный ключ
    ssh_key_passphrase_encrypted = db.Column(db.Text, nullable=True)  # если ключ с паролем
    status = db.Column(db.String(20), default='unknown')  # online, offline, unknown
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Server {self.name} ({self.ip})>'

class ServerProtocol(db.Model):
    __tablename__ = 'server_protocols'

    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    protocol_type = db.Column(db.String(20), nullable=False)  # 'awg', 'xray', 'openvpn'
    port = db.Column(db.Integer, nullable=False)
    config_params = db.Column(db.JSON, default={})  # дополнительные параметры (например, публичный ключ сервера для WG)
    status = db.Column(db.String(20), default='installed')  # installed, installing, error
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    server = db.relationship('Server', backref=db.backref('protocols', lazy=True))

class Client(db.Model):
    __tablename__ = 'clients'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), nullable=True)

    group_id = db.Column(db.Integer, db.ForeignKey('server_groups.id'), nullable=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=True)
    protocol_id = db.Column(db.Integer, db.ForeignKey('server_protocols.id'), nullable=True)
    protocol_type = db.Column(db.String(20)) # 'awg', 'xray' - для групповых клиентов

    # Ключи
    public_key = db.Column(db.Text, nullable=True)  # для WireGuard публичный ключ клиента
    private_key_encrypted = db.Column(db.Text,
                                      nullable=True)  # зашифрованный приватный ключ клиента (для WG) или для XRay не нужен

    # Дополнительные параметры (например, для XRay: uuid, email, shortId)
    extra_params = db.Column(db.JSON, default={})

    # Лимиты
    traffic_limit_bytes = db.Column(db.BigInteger, default=0)  # 0 = безлимит
    traffic_used_bytes = db.Column(db.BigInteger, default=0)
    expiry_date = db.Column(db.DateTime, nullable=True)

    status = db.Column(db.String(20), default='active')  # active, blocked, expired

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    last_stats_update = db.Column(db.DateTime, nullable=True)
    last_limit_check = db.Column(db.DateTime, nullable=True)

    oidc_user_id = db.Column(db.Integer, db.ForeignKey('oidc_users.id'), nullable=True)

    # Связи
    server = db.relationship('Server', backref=db.backref('clients', lazy='dynamic'))
    protocol = db.relationship('ServerProtocol', backref=db.backref('clients', lazy='dynamic'))

    def __repr__(self):
        return f'<Client {self.name}>'

class HaproxyServer(db.Model):
    """Модель для хранения информации о сервере HAProxy"""
    __tablename__ = 'haproxy_servers'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    ip = db.Column(db.String(45), nullable=False)
    port = db.Column(db.Integer, default=22)  # SSH порт
    ssh_username = db.Column(db.String(64), nullable=False)
    ssh_key_encrypted = db.Column(db.Text, nullable=False)
    ssh_key_passphrase_encrypted = db.Column(db.Text, nullable=True)

    # Параметры HAProxy
    config_path = db.Column(db.String(255), default='/etc/haproxy/haproxy.cfg')
    stats_socket_path = db.Column(db.String(255), default='/var/run/haproxy.sock')
    stats_port = db.Column(db.Integer, default=8404)  # для web статистики

    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

class HaproxyBackend(db.Model):
    """Бэкенды HAProxy (соответствуют протоколам)"""
    __tablename__ = 'haproxy_backends'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)  # например 'awg_backend', 'xray_backend'
    protocol_type = db.Column(db.String(20), nullable=False)  # awg, xray, openvpn
    mode = db.Column(db.String(10), default='tcp')  # tcp или http
    balance_algorithm = db.Column(db.String(20), default='roundrobin')
    port = db.Column(db.Integer, nullable=False)  # порт, который слушает фронтенд

    # Связь с HAProxy сервером
    haproxy_server_id = db.Column(db.Integer, db.ForeignKey('haproxy_servers.id'), nullable=False)
    haproxy_server = db.relationship('HaproxyServer', backref=db.backref('backends', lazy=True))

    # Фильтр по группе (опционально)
    group_id = db.Column(db.Integer, db.ForeignKey('server_groups.id'), nullable=True)
    group = db.relationship('ServerGroup', backref='haproxy_backends')

    # Список серверов в этом бэкенде
    servers_json = db.Column(db.JSON, default=[])

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

class ApiToken(db.Model):
    __tablename__ = 'api_tokens'

    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(128), nullable=True)  # описание, для чего токен
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)  # опционально
    is_active = db.Column(db.Boolean, default=True)

    def generate_token(self):
        import secrets
        self.token = secrets.token_urlsafe(32)

class TrafficStats(db.Model):
    """Ежедневная статистика трафика по клиентам"""
    __tablename__ = 'traffic_stats'

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('clients.id', ondelete='CASCADE'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    bytes_sent = db.Column(db.BigInteger, default=0)  # исходящий трафик (tx)
    bytes_received = db.Column(db.BigInteger, default=0)  # входящий трафик (rx)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    client = db.relationship('Client', backref=db.backref('stats', lazy='dynamic', cascade='all, delete-orphan'))

    __table_args__ = (db.UniqueConstraint('client_id', 'date', name='unique_client_date'),)

class OIDCUser(db.Model):
    __tablename__ = 'oidc_users'

    id = db.Column(db.Integer, primary_key=True)
    sub = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), nullable=True)
    name = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    refresh_token_encrypted = db.Column(db.Text, nullable=True)

    clients = db.relationship('Client', backref='oidc_user', lazy='dynamic',
                              foreign_keys='Client.oidc_user_id')


class OIDCSetting(db.Model):
    __tablename__ = 'oidc_settings'

    id = db.Column(db.Integer, primary_key=True)
    provider_url = db.Column(db.String(512), nullable=False)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret_encrypted = db.Column(db.Text, nullable=False)
    # Ручные endpoints (если провайдер не поддерживает .well-known/openid-configuration)
    authorize_url = db.Column(db.String(512), nullable=True)
    token_url = db.Column(db.String(512), nullable=True)
    userinfo_url = db.Column(db.String(512), nullable=True)
    auto_group_id = db.Column(db.Integer, db.ForeignKey('server_groups.id'), nullable=True)
    auto_server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=True)
    auto_protocol_type = db.Column(db.String(20), nullable=True)

    auto_group = db.relationship('ServerGroup', foreign_keys=[auto_group_id])
    auto_server = db.relationship('Server', foreign_keys=[auto_server_id])

    @staticmethod
    def get():
        return OIDCSetting.query.first()


class ServerStats(db.Model):
    """Статистика по серверам (CPU, RAM, нагрузка)"""
    __tablename__ = 'server_stats'

    id = db.Column(db.Integer, primary_key=True)
    server_id = db.Column(db.Integer, db.ForeignKey('servers.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    cpu_usage = db.Column(db.Float)  # процент использования CPU
    memory_usage = db.Column(db.Float)  # процент использования RAM
    load_1min = db.Column(db.Float)  # load average за 1 минуту
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    server = db.relationship('Server', backref=db.backref('stats', lazy='dynamic'))