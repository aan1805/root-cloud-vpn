from flask import render_template, redirect, url_for, flash, request, abort, jsonify
from flask_login import login_required
from app.haproxy import bp
from app.haproxy.manager import HaproxyManager
from app.haproxy.forms import HaproxyServerForm, HaproxyBackendForm
from app.models import HaproxyServer, HaproxyBackend, Server, ServerProtocol
from app.extensions import db
from app.utils.crypto import encrypt_data


@bp.route('/')
@login_required
def index():
    """Главная страница управления HAProxy"""
    haproxy_servers = HaproxyServer.query.all()
    return render_template('haproxy/index.html', servers=haproxy_servers)


@bp.route('/servers/add', methods=['GET', 'POST'])
@login_required
def add_server():
    """Добавление HAProxy сервера"""
    form = HaproxyServerForm()

    if form.validate_on_submit():
        # Шифруем SSH ключи
        encrypted_key = encrypt_data(form.ssh_key.data)
        encrypted_passphrase = None
        if form.ssh_key_passphrase.data:
            encrypted_passphrase = encrypt_data(form.ssh_key_passphrase.data)

        haproxy_server = HaproxyServer(
            name=form.name.data,
            ip=form.ip.data,
            endpoint_domain=(form.endpoint_domain.data or '').strip() or None,
            port=form.ssh_port.data,
            ssh_username=form.ssh_username.data,
            ssh_key_encrypted=encrypted_key,
            ssh_key_passphrase_encrypted=encrypted_passphrase,
            config_path=form.config_path.data,
            stats_socket_path=form.stats_socket_path.data,
            stats_port=form.stats_port.data
        )

        db.session.add(haproxy_server)

        manager = HaproxyManager(haproxy_server)
        success, message =  manager.ensure_haproxy_installed()

        if success:
            db.session.commit()
            flash(message, 'success')
        else:
            db.session.rollback()
            flash(message, 'danger')
        return redirect(url_for('haproxy.index'))

    return render_template('haproxy/add_server.html', form=form)


@bp.route('/servers/<int:server_id>')
@login_required
def view_server(server_id):
    """Просмотр информации о HAProxy сервере"""
    server = HaproxyServer.query.get_or_404(server_id)
    manager = HaproxyManager(server)

    # Получаем статус HAProxy
    _, version, _ = manager._execute_ssh("haproxy -v | head -1")
    _, stats, _ = manager._execute_ssh("systemctl status haproxy --no-pager")

    # Получаем список бэкендов
    backends = HaproxyBackend.query.filter_by(haproxy_server_id=server_id).all()

    return render_template('haproxy/view_server.html',
                           server=server,
                           version=version,
                           stats=stats,
                           backends=backends)


@bp.route('/servers/<int:server_id>/backends/add', methods=['GET', 'POST'])
@login_required
def add_backend(server_id):
    """Добавление бэкенда для HAProxy сервера"""
    server = HaproxyServer.query.get_or_404(server_id)
    form = HaproxyBackendForm()
    
    from app.models import ServerGroup
    form.group_id.choices = [(0, '--- Все серверы ---')] + [(g.id, g.name) for g in ServerGroup.query.order_by(ServerGroup.name).all()]

    if form.validate_on_submit():
        backend = HaproxyBackend(
            name=form.name.data,
            protocol_type=form.protocol_type.data,
            mode=form.mode.data,
            balance_algorithm=form.balance_algorithm.data,
            port=form.port.data,
            haproxy_server_id=server_id,
            group_id=form.group_id.data if form.group_id.data and form.group_id.data > 0 else None,
            servers_json=[]
        )

        db.session.add(backend)
        db.session.commit()

        # Обновляем конфигурацию HAProxy
        success, message = update_haproxy_config(server)
        if success:
            flash('Бэкенд добавлен и конфигурация HAProxy обновлена', 'success')
        else:
            flash(f'Бэкенд добавлен в БД, но ошибка применения конфига HAProxy: {message}', 'warning')

        return redirect(url_for('haproxy.view_server', server_id=server_id))

    return render_template('haproxy/add_backend.html', form=form, server=server)


@bp.route('/backends/<int:backend_id>/sync')
@login_required
def sync_backend(backend_id):
    """Синхронизирует бэкенд с серверами Amnezia"""
    backend = HaproxyBackend.query.get_or_404(backend_id)

    # Находим серверы Amnezia
    query = Server.query.filter_by(status='online')
    if backend.group_id:
        query = query.filter_by(group_id=backend.group_id)
    
    servers = query.all()
    backend_servers = []

    for server in servers:
        protocol = ServerProtocol.query.filter_by(
            server_id=server.id,
            protocol_type=backend.protocol_type,
            status='installed'
        ).first()

        if protocol:
            backend_servers.append({
                'name': f"s{server.id}",
                'ip': server.ip,
                'port': protocol.port,
                'status': 'active'
            })

    # Обновляем список серверов в бэкенде
    backend.servers_json = backend_servers
    db.session.commit()

    haproxy_server = HaproxyServer.query.get(backend.haproxy_server_id)

    if backend.protocol_type == 'awg':
        # AWG — UDP через nginx, нужен полный config update (socket-команды HAProxy не подходят)
        success, message = update_haproxy_config(haproxy_server)
    else:
        # TCP протоколы — динамическое обновление через HAProxy stats socket
        success, message = update_haproxy_backend(haproxy_server, backend)

    if success:
        flash('Бэкенд синхронизирован', 'success')
    else:
        flash(f'Ошибка синхронизации: {message}', 'danger')

    return redirect(url_for('haproxy.view_server', server_id=backend.haproxy_server_id))


@bp.route('/backends/<int:backend_id>/enable', methods=['POST'])
@login_required
def enable_backend(backend_id):
    """Включает бэкенд"""
    backend = HaproxyBackend.query.get_or_404(backend_id)
    server = HaproxyServer.query.get(backend.haproxy_server_id)
    manager = HaproxyManager(server)

    for srv in backend.servers_json:
        manager.enable_server(backend.name, srv['name'])

    flash('Все серверы в бэкенде включены', 'success')
    return redirect(url_for('haproxy.view_server', server_id=backend.haproxy_server_id))


@bp.route('/backends/<int:backend_id>/disable', methods=['POST'])
@login_required
def disable_backend(backend_id):
    """Отключает бэкенд"""
    backend = HaproxyBackend.query.get_or_404(backend_id)
    server = HaproxyServer.query.get(backend.haproxy_server_id)
    manager = HaproxyManager(server)

    for srv in backend.servers_json:
        manager.disable_server(backend.name, srv['name'])

    flash('Все серверы в бэкенде отключены', 'success')
    return redirect(url_for('haproxy.view_server', server_id=backend.haproxy_server_id))


@bp.route('/servers/<int:server_id>/reload', methods=['POST'])
@login_required
def reload_haproxy(server_id):
    """Перезагружает HAProxy"""
    server = HaproxyServer.query.get_or_404(server_id)
    manager = HaproxyManager(server)

    success, message = manager.reload()
    if success:
        flash('HAProxy перезагружен', 'success')
    else:
        flash(f'Ошибка: {message}', 'danger')

    return redirect(url_for('haproxy.view_server', server_id=server_id))


@bp.route('/servers/<int:server_id>/delete', methods=['POST'])
@login_required
def delete_server(server_id):
    """Удаляет HAProxy сервер и все его бэкенды"""
    server = HaproxyServer.query.get_or_404(server_id)
    # Удаляем все бэкенды сервера, затем сам сервер
    HaproxyBackend.query.filter_by(haproxy_server_id=server_id).delete()
    db.session.delete(server)
    db.session.commit()
    flash(f'HAProxy сервер «{server.name}» удалён.', 'success')
    return redirect(url_for('haproxy.index'))


@bp.route('/backends/<int:backend_id>/delete', methods=['POST'])
@login_required
def delete_backend(backend_id):
    """Удаляет бэкенд"""
    backend = HaproxyBackend.query.get_or_404(backend_id)
    server_id = backend.haproxy_server_id
    server = HaproxyServer.query.get(server_id)
    
    db.session.delete(backend)
    db.session.commit()
    
    # Обновляем конфиг HAProxy (удаляем секцию бэкенда из файла)
    update_haproxy_config(server)
    
    flash('Бэкенд удален', 'success')
    return redirect(url_for('haproxy.view_server', server_id=server_id))


def _collect_servers_for_backend(backend):
    """Возвращает список серверов для бэкенда на основе группы и статуса."""
    query = Server.query.filter_by(status='online')
    if backend.group_id:
        query = query.filter_by(group_id=backend.group_id)

    servers = []
    for s in query.all():
        proto = ServerProtocol.query.filter_by(
            server_id=s.id, protocol_type=backend.protocol_type, status='installed'
        ).first()
        if proto:
            servers.append({'name': f"s{s.id}", 'ip': s.ip, 'port': proto.port, 'status': 'active'})
    return servers


def _build_haproxy_sections(haproxy_server, manager):
    """Генерирует HAProxy frontend/backend секции только для TCP протоколов (xray, openvpn)."""
    sections = []
    backends = HaproxyBackend.query.filter_by(haproxy_server_id=haproxy_server.id).all()
    for backend in backends:
        if backend.protocol_type == 'awg':
            continue  # AWG — UDP, обрабатывается nginx

        backend.servers_json = _collect_servers_for_backend(backend)
        sections.append(manager.generate_backend_config(backend))
        sections.append(manager.generate_frontend_config(backend))
    return sections


def update_haproxy_config(haproxy_server):
    """
    Обновляет конфигурации на прокси-сервере:
    - AWG (UDP) → nginx stream
    - XRay / OpenVPN (TCP) → HAProxy
    """
    manager = HaproxyManager(haproxy_server)

    # --- nginx: AWG бэкенды ---
    awg_backends = HaproxyBackend.query.filter_by(
        haproxy_server_id=haproxy_server.id, protocol_type='awg'
    ).all()
    for b in awg_backends:
        b.servers_json = _collect_servers_for_backend(b)

    nginx_ok, nginx_msg = manager.update_nginx_stream_config(awg_backends)

    # --- HAProxy: TCP бэкенды ---
    has_tcp = HaproxyBackend.query.filter(
        HaproxyBackend.haproxy_server_id == haproxy_server.id,
        HaproxyBackend.protocol_type != 'awg'
    ).first() is not None

    haproxy_ok, haproxy_msg = True, "Нет TCP бэкендов"
    if has_tcp:
        exit_code, current_config, err = manager.get_config()
        if exit_code != 0:
            haproxy_ok, haproxy_msg = False, f"Не удалось прочитать конфиг HAProxy: {err}"
        else:
            lines = current_config.split('\n')
            new_lines = []
            in_auto_section = False
            markers_found = '# BEGIN AUTO GENERATED' in current_config

            for line in lines:
                if '# BEGIN AUTO GENERATED' in line:
                    in_auto_section = True
                    new_lines.append(line)
                    for section in _build_haproxy_sections(haproxy_server, manager):
                        new_lines.append(section)
                elif '# END AUTO GENERATED' in line:
                    in_auto_section = False
                    new_lines.append(line)
                elif not in_auto_section:
                    new_lines.append(line)

            if not markers_found:
                new_lines.append('\n# BEGIN AUTO GENERATED')
                for section in _build_haproxy_sections(haproxy_server, manager):
                    new_lines.append(section)
                new_lines.append('# END AUTO GENERATED')

            new_config = '\n'.join(new_lines)
            haproxy_ok, haproxy_msg = manager.save_config(new_config)
            if haproxy_ok:
                haproxy_ok, haproxy_msg = manager.reload()

    db.session.commit()

    if nginx_ok and haproxy_ok:
        return True, "Конфигурация обновлена"
    errors = []
    if not nginx_ok:
        errors.append(f"nginx: {nginx_msg}")
    if not haproxy_ok:
        errors.append(f"haproxy: {haproxy_msg}")
    return False, "; ".join(errors)


def update_haproxy_backend(haproxy_server, backend):
    """Обновляет конкретный бэкенд в HAProxy"""
    manager = HaproxyManager(haproxy_server)

    # Получаем текущие серверы в бэкенде
    current_servers = {}
    exit_code, out, err = manager._execute_socket_command(f"show servers state {backend.name}")
    if exit_code == 0:
        for line in out.split('\n'):
            if line.startswith(f'{backend.name},'):
                parts = line.split(',')
                if len(parts) >= 2:
                    srv_name = parts[1]
                    current_servers[srv_name] = True

    # Добавляем новые серверы
    for srv in backend.servers_json:
        if srv['name'] not in current_servers:
            manager.add_server_to_backend(backend.name, srv['name'], srv['ip'], srv['port'])

    # Удаляем серверы, которых нет в конфиге
    for srv_name in current_servers:
        found = False
        for srv in backend.servers_json:
            if srv['name'] == srv_name:
                found = True
                break
        if not found:
            manager.remove_server_from_backend(backend.name, srv_name)

    return True, "Бэкенд обновлён"