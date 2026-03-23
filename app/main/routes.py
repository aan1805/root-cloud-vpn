from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required
from app.main import bp
from app.models import ApiToken, OIDCSetting, ServerGroup, Server
from app.extensions import db
from app.utils.crypto import encrypt_data
from datetime import datetime

@bp.route('/settings/tokens')
@login_required
def tokens():
    tokens = ApiToken.query.order_by(ApiToken.created_at.desc()).all()
    return render_template('settings/tokens.html', tokens=tokens)

@bp.route('/settings/tokens/create', methods=['POST'])
@login_required
def create_token():
    name = request.form.get('name')
    token = ApiToken(name=name, is_active=True)
    token.generate_token()
    db.session.add(token)
    db.session.commit()
    flash(f'Токен создан: {token.token}', 'success')
    return redirect(url_for('main.tokens'))

@bp.route('/settings/tokens/<int:id>/toggle', methods=['POST'])
@login_required
def toggle_token(id):
    token = ApiToken.query.get_or_404(id)
    token.is_active = not token.is_active
    db.session.commit()
    flash(f'Токен {"активирован" if token.is_active else "деактивирован"}', 'success')
    return redirect(url_for('main.tokens'))

@bp.route('/settings/tokens/<int:id>/delete', methods=['POST'])
@login_required
def delete_token(id):
    token = ApiToken.query.get_or_404(id)
    db.session.delete(token)
    db.session.commit()
    flash('Токен удалён', 'success')
    return redirect(url_for('main.tokens'))


@bp.route('/settings/oidc', methods=['GET', 'POST'])
@login_required
def oidc_settings():
    setting = OIDCSetting.get()
    groups = ServerGroup.query.order_by(ServerGroup.name).all()
    servers = Server.query.order_by(Server.name).all()

    if request.method == 'POST':
        provider_url = request.form.get('provider_url', '').strip()
        client_id = request.form.get('client_id', '').strip()
        client_secret = request.form.get('client_secret', '').strip()
        authorize_url = request.form.get('authorize_url', '').strip() or None
        token_url = request.form.get('token_url', '').strip() or None
        userinfo_url = request.form.get('userinfo_url', '').strip() or None
        auto_group_id = request.form.get('auto_group_id') or None
        auto_server_id = request.form.get('auto_server_id') or None
        auto_protocol_type = request.form.get('auto_protocol_type') or None

        if not provider_url or not client_id:
            flash('Provider URL и Client ID обязательны.', 'danger')
            return render_template('settings/oidc.html', setting=setting, groups=groups, servers=servers)

        if setting is None:
            if not client_secret:
                flash('Client Secret обязателен при первичной настройке.', 'danger')
                return render_template('settings/oidc.html', setting=setting, groups=groups, servers=servers)
            setting = OIDCSetting()
            db.session.add(setting)

        setting.provider_url = provider_url
        setting.client_id = client_id
        if client_secret:
            setting.client_secret_encrypted = encrypt_data(client_secret)
        setting.authorize_url = authorize_url
        setting.token_url = token_url
        setting.userinfo_url = userinfo_url
        setting.auto_group_id = int(auto_group_id) if auto_group_id else None
        setting.auto_server_id = int(auto_server_id) if auto_server_id else None
        setting.auto_protocol_type = auto_protocol_type
        db.session.commit()
        flash('Настройки OIDC сохранены.', 'success')
        return redirect(url_for('main.oidc_settings'))

    return render_template('settings/oidc.html', setting=setting, groups=groups, servers=servers)