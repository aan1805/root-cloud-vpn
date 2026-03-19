import secrets
from functools import wraps
from flask import request, jsonify, session
from flask_login import login_required

from app import db
from app.api import bp
from app.models import ApiToken
from datetime import datetime


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Ищем токен в заголовке Authorization: Bearer <token>
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                token = parts[1]

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        # Проверяем токен в БД
        api_token = ApiToken.query.filter_by(token=token, is_active=True).first()
        if not api_token:
            return jsonify({'error': 'Invalid or inactive token'}), 401

        # Обновляем время последнего использования
        api_token.last_used_at = datetime.utcnow()
        db.session.commit()

        return f(*args, **kwargs)

    return decorated

def get_or_create_session_token():
    """Создаёт или возвращает существующий токен для текущей сессии"""
    if 'api_token' not in session:
        # Создаём новый токен для сессии
        token = ApiToken(
            name=f"session_token_{secrets.token_hex(8)}",
            is_active=True
        )
        token.generate_token()
        db.session.add(token)
        db.session.commit()
        session['api_token'] = token.token
        session.permanent = True
    return session['api_token']

@bp.route('/session-token', methods=['GET'])
@login_required  # используем обычную Flask-Login аутентификацию
def get_session_token():
    """Возвращает токен для текущей сессии"""
    token = get_or_create_session_token()
    return jsonify({'token': token})