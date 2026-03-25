from flask import render_template, redirect, url_for, flash, request
from flask_login import login_required

from app.haproxy.manager import HaproxyManager
from app.servers import bp
from app.servers.forms import ServerForm
from app.servers.ssh import test_ssh_connection
from app.models import Server, HaproxyBackend, HaproxyServer, ServerGroup
from app.extensions import db
from app.utils.crypto import encrypt_data, decrypt_data

@bp.route('/')
@login_required
def index():
    servers = Server.query.order_by(Server.created_at.desc()).all()
    return render_template('servers/index.html', servers=servers)

@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = ServerForm()
    form.group_id.choices = [(0, '--- Без группы ---')] + [(g.id, g.name) for g in ServerGroup.query.order_by(ServerGroup.name).all()]
    
    if form.validate_on_submit():
        # Проверяем SSH-подключение перед сохранением
        ip = form.ip.data
        port = form.ssh_port.data
        username = form.ssh_username.data
        key = form.ssh_key.data
        passphrase = form.ssh_key_passphrase.data

        success, error = test_ssh_connection(ip, port, username, key, passphrase)
        if not success:
            flash(f'Ошибка подключения по SSH: {error}', 'danger')
            return render_template('servers/form.html', form=form)

        # Шифруем ключ и пароль перед сохранением
        encrypted_key = encrypt_data(key)
        encrypted_passphrase = encrypt_data(passphrase) if passphrase else None

        server = Server(
            name=form.name.data,
            group_id=form.group_id.data if form.group_id.data > 0 else None,
            ip=ip,
            ssh_port=port,
            ssh_username=username,
            ssh_key_encrypted=encrypted_key,
            ssh_key_passphrase_encrypted=encrypted_passphrase,
            is_public=form.is_public.data,
            status='online'  # после успешной проверки считаем онлайн
        )
        db.session.add(server)
        db.session.commit()
        flash('Сервер успешно добавлен', 'success')
        return redirect(url_for('servers.index'))

    return render_template('servers/form.html', form=form, title='Добавление сервера')

@bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    server = Server.query.get_or_404(id)
    form = ServerForm(obj=server)
    form.group_id.choices = [(0, '--- Без группы ---')] + [(g.id, g.name) for g in ServerGroup.query.order_by(ServerGroup.name).all()]
    
    if form.validate_on_submit():
        # Обновляем данные
        ip = form.ip.data
        port = form.ssh_port.data
        username = form.ssh_username.data
        key = form.ssh_key.data
        passphrase = form.ssh_key_passphrase.data

        # Если ключ не передан (поле пустое), оставляем старый
        if key:
            # Проверка подключения с новым ключом
            success, error = test_ssh_connection(ip, port, username, key, passphrase)
            if not success:
                flash(f'Ошибка подключения по SSH: {error}', 'danger')
                return render_template('servers/form.html', form=form, server=server)
            encrypted_key = encrypt_data(key)
            encrypted_passphrase = encrypt_data(passphrase) if passphrase else None
            server.ssh_key_encrypted = encrypted_key
            server.ssh_key_passphrase_encrypted = encrypted_passphrase

        # Обновляем остальные поля
        server.name = form.name.data
        server.group_id = form.group_id.data if form.group_id.data > 0 else None
        server.ip = ip
        server.ssh_port = port
        server.ssh_username = username
        server.is_public = form.is_public.data
        # статус проверим позже в фоновой задаче, пока оставляем
        db.session.commit()
        flash('Сервер обновлен', 'success')
        return redirect(url_for('servers.index'))

    # Для отображения существующего ключа не передаем его в форму
    form.ssh_key.data = ''  # очищаем, чтобы не показывать зашифрованный
    if server.group_id:
        form.group_id.data = server.group_id
    return render_template('servers/form.html', form=form, server=server, title='Редактирование сервера')

@bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    server = Server.query.get_or_404(id)
    db.session.delete(server)
    db.session.commit()
    flash('Сервер удален', 'success')
    return redirect(url_for('servers.index'))

@bp.route('/<int:id>/check')
@login_required
def check_status(id):
    server = Server.query.get_or_404(id)
    # Расшифровываем ключ
    key = decrypt_data(server.ssh_key_encrypted)
    passphrase = decrypt_data(server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None
    success, error = test_ssh_connection(server.ip, server.ssh_port, server.ssh_username, key, passphrase)
    if success:
        server.status = 'online'
        flash('Сервер доступен', 'success')
    else:
        server.status = 'offline'
        flash(f'Сервер недоступен: {error}', 'warning')
    db.session.commit()
    return redirect(url_for('servers.index'))


def update_haproxy_after_protocol_install(server, protocol):
    """Обновляет HAProxy после установки протокола на сервере"""
    haproxy_servers = HaproxyServer.query.filter_by(status='active').all()

    for haproxy in haproxy_servers:
        # Находим соответствующий бэкенд
        backend = HaproxyBackend.query.filter_by(
            haproxy_server_id=haproxy.id,
            protocol_type=protocol.protocol_type
        ).first()

        if backend:
            # Добавляем сервер в список
            server_entry = {
                'name': f"s{server.id}_{server.name.replace(' ', '_')}",
                'ip': server.ip,
                'port': protocol.port,
                'status': 'active'
            }

            if server_entry not in backend.servers_json:
                backend.servers_json.append(server_entry)
                db.session.commit()

                # Добавляем в HAProxy динамически
                manager = HaproxyManager(haproxy)
                manager.add_server_to_backend(
                    backend.name,
                    server_entry['name'],
                    server.ip,
                    protocol.port
                )