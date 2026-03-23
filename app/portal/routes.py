from flask import render_template, redirect, url_for, session, request, current_app, Response, abort
from app.portal import bp
from app.models import OIDCSetting, OIDCUser, Client, ServerProtocol, Server
from app.extensions import db
from app.utils.crypto import decrypt_data
from app.clients.utils import generate_keys_for_client, generate_client_config
from app.tasks import apply_client_task
from datetime import datetime
import functools


def portal_login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if 'portal_user_id' not in session:
            return redirect(url_for('portal.login'))
        return f(*args, **kwargs)
    return decorated


def _get_oauth_client():
    setting = OIDCSetting.get()
    if not setting:
        return None, None
    try:
        from authlib.integrations.flask_client import OAuth
        oauth = OAuth(current_app)

        if setting.authorize_url and setting.token_url:
            # Ручные endpoints — провайдер без discovery
            kwargs = dict(
                client_id=setting.client_id,
                client_secret=decrypt_data(setting.client_secret_encrypted),
                authorize_url=setting.authorize_url,
                access_token_url=setting.token_url,
                client_kwargs={'scope': 'openid email profile'},
            )
            if setting.userinfo_url:
                kwargs['userinfo_endpoint'] = setting.userinfo_url
        else:
            # Стандартный OIDC с auto-discovery
            kwargs = dict(
                client_id=setting.client_id,
                client_secret=decrypt_data(setting.client_secret_encrypted),
                server_metadata_url=f"{setting.provider_url.rstrip('/')}/.well-known/openid-configuration",
                client_kwargs={'scope': 'openid email profile'},
            )

        oauth.register('provider', **kwargs)
        return oauth, oauth.provider
    except Exception as e:
        current_app.logger.error(f"OAuth client init error: {e}")
        return None, None


def _auto_provision_client(user, setting):
    """Create a VPN client for a new OIDC user."""
    client = Client(
        name=user.name or user.email or f"portal_{user.sub[:8]}",
        email=user.email,
        oidc_user_id=user.id,
        status='pending'
    )

    if setting.auto_group_id:
        client.group_id = setting.auto_group_id
        client.protocol_type = setting.auto_protocol_type
    elif setting.auto_server_id:
        server = Server.query.get(setting.auto_server_id)
        if server:
            protocol = ServerProtocol.query.filter_by(
                server_id=server.id,
                protocol_type=setting.auto_protocol_type,
                status='installed'
            ).first()
            if protocol:
                client.server_id = server.id
                client.protocol_id = protocol.id
                client.protocol_type = setting.auto_protocol_type

    db.session.add(client)
    db.session.commit()

    try:
        generate_keys_for_client(client)
        apply_client_task.delay(client.id)
    except Exception as e:
        current_app.logger.error(f"Portal provision error for user {user.id}: {e}")

    return client


@bp.route('/')
@portal_login_required
def index():
    user = OIDCUser.query.get(session['portal_user_id'])
    if not user:
        session.pop('portal_user_id', None)
        return redirect(url_for('portal.login'))

    setting = OIDCSetting.get()
    if not setting:
        return render_template('portal/not_configured.html')

    clients = user.clients.all()

    # Auto-provision if no clients yet
    if not clients and setting.auto_protocol_type:
        _auto_provision_client(user, setting)
        clients = user.clients.all()

    return render_template('portal/index.html', user=user, clients=clients)


@bp.route('/login')
def login():
    setting = OIDCSetting.get()
    if not setting:
        return render_template('portal/not_configured.html')

    oauth, provider = _get_oauth_client()
    if not provider:
        return render_template('portal/not_configured.html')

    redirect_uri = url_for('portal.callback', _external=True)
    return provider.authorize_redirect(redirect_uri)


@bp.route('/callback')
def callback():
    setting = OIDCSetting.get()
    if not setting:
        return render_template('portal/not_configured.html')

    oauth, provider = _get_oauth_client()
    if not provider:
        return render_template('portal/not_configured.html')

    try:
        token = provider.authorize_access_token()
        current_app.logger.info(f"OIDC token received, keys: {list(token.keys())}")
    except Exception as e:
        import traceback
        current_app.logger.error(f"OIDC token exchange error: {e}\n{traceback.format_exc()}")
        return render_template('portal/not_configured.html',
                               error=f"Ошибка обмена токена: {e}")

    try:
        # Для провайдеров без discovery userinfo не парсится автоматически из id_token
        userinfo = token.get('userinfo')
        if not userinfo and setting.userinfo_url:
            userinfo = provider.userinfo(token=token)
            current_app.logger.info(f"OIDC userinfo fetched: {userinfo}")
        if not userinfo:
            # fallback: взять claims прямо из токена
            userinfo = dict(token)
            current_app.logger.info(f"OIDC userinfo fallback from token: {list(userinfo.keys())}")
    except Exception as e:
        import traceback
        current_app.logger.error(f"OIDC userinfo error: {e}\n{traceback.format_exc()}")
        return render_template('portal/not_configured.html',
                               error=f"Ошибка получения данных пользователя: {e}")

    sub = userinfo.get('sub')
    if not sub:
        return render_template('portal/not_configured.html', error="Не удалось получить данные пользователя.")

    user = OIDCUser.query.filter_by(sub=sub).first()
    is_new = user is None

    if user is None:
        user = OIDCUser(
            sub=sub,
            email=userinfo.get('email'),
            name=userinfo.get('name') or userinfo.get('preferred_username')
        )
        db.session.add(user)
    else:
        user.email = userinfo.get('email', user.email)
        user.name = userinfo.get('name') or userinfo.get('preferred_username') or user.name

    user.last_login = datetime.utcnow()
    db.session.commit()

    session['portal_user_id'] = user.id

    # Auto-provision for new users
    if is_new and setting.auto_protocol_type:
        _auto_provision_client(user, setting)

    return redirect(url_for('portal.index'))


@bp.route('/logout')
def logout():
    session.pop('portal_user_id', None)
    return redirect(url_for('portal.login'))


@bp.route('/client/<int:client_id>/config')
@portal_login_required
def download_config(client_id):
    user = OIDCUser.query.get(session['portal_user_id'])
    if not user:
        abort(403)

    client = Client.query.get_or_404(client_id)
    if client.oidc_user_id != user.id:
        abort(403)

    config = generate_client_config(client)
    if not config:
        abort(404)

    filename = f"{client.name}.conf"
    return Response(
        config,
        mimetype='text/plain',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


@bp.route('/client/<int:client_id>/config-text')
@portal_login_required
def config_text(client_id):
    """Plain text config for QR code generation (no download header)."""
    user = OIDCUser.query.get(session['portal_user_id'])
    if not user:
        abort(403)

    client = Client.query.get_or_404(client_id)
    if client.oidc_user_id != user.id:
        abort(403)

    config = generate_client_config(client)
    if not config:
        abort(404)

    return Response(config, mimetype='text/plain')
