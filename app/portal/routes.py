from flask import render_template, redirect, url_for, session, request, current_app, Response, abort, flash
from app.portal import bp
from app.models import OIDCSetting, OIDCUser, Client, ServerProtocol, Server, ServerGroup
from app.extensions import db
from app.utils.crypto import decrypt_data, encrypt_data
from app.clients.utils import generate_keys_for_client, generate_client_config, generate_amnezia_export_json, resolve_client_endpoint
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
                token_endpoint_auth_method='client_secret_post',
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
                token_endpoint_auth_method='client_secret_post',
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


def _get_portal_user():
    user = OIDCUser.query.get(session.get('portal_user_id'))
    if not user:
        session.pop('portal_user_id', None)
    return user


def _available_options(user=None):
    """Возвращает серверы и группы с установленными протоколами с учётом видимости."""
    allowed_server_ids = set()
    allowed_group_ids = set()
    if user:
        allowed_server_ids = {s.id for s in user.allowed_servers}
        allowed_group_ids = {g.id for g in user.allowed_groups}

    servers = []
    for s in Server.query.filter_by(status='online').all():
        if not s.is_public and s.id not in allowed_server_ids:
            continue
        protos = [p.protocol_type for p in s.protocols if p.status == 'installed']
        if protos:
            servers.append({'obj': s, 'protocols': protos})

    groups = []
    for g in ServerGroup.query.all():
        if not g.is_public and g.id not in allowed_group_ids:
            continue
        protos = set()
        for s in g.servers:
            for p in s.protocols:
                if p.status == 'installed':
                    protos.add(p.protocol_type)
        if protos:
            groups.append({'obj': g, 'protocols': sorted(protos)})

    return servers, groups


@bp.route('/')
@portal_login_required
def index():
    user = _get_portal_user()
    if not user:
        return redirect(url_for('portal.login'))

    if not OIDCSetting.get():
        return render_template('portal/not_configured.html')

    clients = user.clients.all()
    return render_template('portal/index.html', user=user, clients=clients)


@bp.route('/create', methods=['GET', 'POST'])
@portal_login_required
def create_client():
    user = _get_portal_user()
    if not user:
        return redirect(url_for('portal.login'))

    servers, groups = _available_options(user)

    if request.method == 'POST':
        # Проверяем лимит клиентов
        if user.client_limit > 0 and user.clients.count() >= user.client_limit:
            flash(f'Достигнут лимит клиентов ({user.client_limit}). Обратитесь к администратору.', 'danger')
            return render_template('portal/create.html', user=user, servers=servers, groups=groups)

        target_type = request.form.get('target_type')  # 'server' or 'group'
        target_id = request.form.get('target_id', type=int)
        protocol_type = request.form.get('protocol_type')

        if not target_type or not target_id or not protocol_type:
            flash('Заполните все поля.', 'danger')
            return render_template('portal/create.html', user=user,
                                   servers=servers, groups=groups)

        client = Client(
            email=user.email,
            oidc_user_id=user.id,
            status='pending',
        )

        if target_type == 'server':
            server = Server.query.get_or_404(target_id)
            protocol = ServerProtocol.query.filter_by(
                server_id=server.id,
                protocol_type=protocol_type,
                status='installed'
            ).first()
            if not protocol:
                flash('Протокол не найден на этом сервере.', 'danger')
                return render_template('portal/create.html', user=user,
                                       servers=servers, groups=groups)
            client.name = f"{user.name or user.email or 'user'}_{server.name}_{protocol_type}"
            client.server_id = server.id
            client.protocol_id = protocol.id
            client.protocol_type = protocol_type

        elif target_type == 'group':
            group = ServerGroup.query.get_or_404(target_id)
            client.name = f"{user.name or user.email or 'user'}_{group.name}_{protocol_type}"
            client.group_id = group.id
            client.protocol_type = protocol_type

        else:
            abort(400)

        db.session.add(client)
        db.session.commit()

        try:
            generate_keys_for_client(client)
            apply_client_task.delay(client.id)
        except Exception as e:
            current_app.logger.error(f"Portal create client error: {e}")
            flash(f'Ошибка создания конфига: {e}', 'danger')
            db.session.delete(client)
            db.session.commit()
            return render_template('portal/create.html', user=user,
                                   servers=servers, groups=groups)

        flash('Конфиг создаётся, обычно это занимает несколько секунд.', 'success')
        return redirect(url_for('portal.index'))

    return render_template('portal/create.html', user=user,
                           servers=servers, groups=groups)


@bp.route('/client/<int:client_id>/delete', methods=['POST'])
@portal_login_required
def delete_client(client_id):
    user = _get_portal_user()
    if not user:
        return redirect(url_for('portal.login'))

    client = Client.query.get_or_404(client_id)
    if client.oidc_user_id != user.id:
        abort(403)

    from app.tasks import remove_client_task
    remove_client_task.delay(client.id)
    flash('Конфиг удаляется.', 'info')
    return redirect(url_for('portal.index'))


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
        default_limit = setting.default_client_limit if setting else 0
        user = OIDCUser(
            sub=sub,
            email=userinfo.get('email'),
            name=userinfo.get('name') or userinfo.get('preferred_username'),
            client_limit=default_limit
        )
        db.session.add(user)
    else:
        user.email = userinfo.get('email', user.email)
        user.name = userinfo.get('name') or userinfo.get('preferred_username') or user.name

    user.last_login = datetime.utcnow()

    refresh_token = token.get('refresh_token')
    if refresh_token:
        user.refresh_token_encrypted = encrypt_data(refresh_token)

    db.session.commit()

    session['portal_user_id'] = user.id
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

    try:
        config = generate_client_config(client)
    except Exception as e:
        import traceback
        current_app.logger.error(f"download_config error for client {client_id}: {e}\n{traceback.format_exc()}")
        flash('Ошибка генерации конфига. Проверьте логи.', 'danger')
        return redirect(url_for('portal.index'))

    if not config:
        current_app.logger.warning(f"download_config: empty config for client {client_id}")
        flash('Не удалось сформировать конфиг — сервер недоступен или не настроен.', 'danger')
        return redirect(url_for('portal.index'))

    from urllib.parse import quote
    filename = f"{client.name}.conf"
    filename_encoded = quote(filename, safe='')
    return Response(
        config,
        mimetype='text/plain',
        headers={'Content-Disposition': f"attachment; filename*=UTF-8''{filename_encoded}"}
    )


@bp.route('/client/<int:client_id>/config-text')
@portal_login_required
def config_text(client_id):
    """Config for QR code generation. AWG → Amnezia JSON export; XRay → vless:// URI."""
    user = OIDCUser.query.get(session['portal_user_id'])
    if not user:
        abort(403)

    client = Client.query.get_or_404(client_id)
    if client.oidc_user_id != user.id:
        abort(403)

    proto_type = client.protocol_type or (client.protocol.protocol_type if client.protocol else None)

    try:
        if proto_type == 'awg':
            connection_address, connection_port = resolve_client_endpoint(client)
            if not connection_address or not connection_port:
                return Response('', mimetype='text/plain', status=404)
            text = generate_amnezia_export_json(client, connection_address, connection_port)
        else:
            text = generate_client_config(client)

    except Exception as e:
        import traceback
        current_app.logger.error(f"config_text error for client {client_id}: {e}\n{traceback.format_exc()}")
        return Response('ERROR', mimetype='text/plain', status=500)

    if not text:
        return Response('', mimetype='text/plain', status=404)

    return Response(text, mimetype='text/plain')
