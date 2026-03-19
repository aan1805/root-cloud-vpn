from flask import render_template, redirect, url_for, flash, request, abort, current_app
from flask_login import login_required
from app.protocols import bp
from app.protocols.forms import ProtocolInstallForm
from app.protocols.docker_installer import (
    get_protocol_status
)
from app.protocols.utils import install_protocol_on_server, uninstall_protocol
from app.models import Server, ServerProtocol
from app.extensions import db
from app.servers.ssh import execute_ssh_command
from app.utils.crypto import decrypt_data
from app.tasks import install_protocol_task, uninstall_protocol_task, restart_protocol_task


@bp.route('/')
@login_required
def index(server_id):
    server = Server.query.get_or_404(server_id)
    protocols = ServerProtocol.query.filter_by(server_id=server_id).all()

    key = decrypt_data(server.ssh_key_encrypted)
    passphrase = decrypt_data(server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None

    status = {}

    # Получаем статус контейнеров для каждого протокола
    for proto in protocols:
        if proto.status == 'installed':
            exit_code, stdout, stderr = execute_ssh_command(
                server.ip, server.ssh_port, server.ssh_username,
                key, get_protocol_status(proto.protocol_type), passphrase
            )
            status[proto.protocol_type] = True if exit_code == 0 and "Up" in stdout else False
        else:
            status[proto.protocol_type] = proto.status

    return render_template('protocols/index.html', server=server, protocols=protocols, status=status)


@bp.route('/install', methods=['GET', 'POST'])
@login_required
def install(server_id):
    server = Server.query.get_or_404(server_id)
    form = ProtocolInstallForm()

    if form.validate_on_submit():
        protocol_type = form.protocol_type.data
        port = form.port.data

        # Проверяем, не установлен ли уже такой протокол
        existing = ServerProtocol.query.filter_by(server_id=server_id, protocol_type=protocol_type).first()
        if existing:
            flash(f'Протокол {protocol_type} уже установлен на этом сервере.', 'warning')
            return redirect(url_for('protocols.index', server_id=server_id))

        # Создаем запись со статусом 'installing'
        protocol = ServerProtocol(
            server_id=server_id,
            protocol_type=protocol_type,
            port=port,
            status='installing'
        )
        db.session.add(protocol)
        db.session.commit()

        # Запускаем установку асинхронно
        install_protocol_task.delay(protocol.id)
        
        flash(f'Запущена установка протокола {protocol_type}. Это может занять несколько минут.', 'info')
        return redirect(url_for('protocols.index', server_id=server_id))

    return render_template('protocols/install.html', server=server, form=form)


@bp.route('/<int:protocol_id>/delete', methods=['POST'])
@login_required
def delete(server_id, protocol_id):
    protocol = ServerProtocol.query.get_or_404(protocol_id)
    if protocol.server_id != server_id:
        abort(404)

    if protocol.clients.count() > 0:
        flash(f'Ошибка при удалении: есть активные клиенты ({protocol.clients.count()})', 'danger')
        return redirect(url_for('protocols.index', server_id=server_id))

    # Запускаем удаление асинхронно
    uninstall_protocol_task.delay(protocol.id)
    flash(f'Запущено удаление протокола {protocol.protocol_type}.', 'info')

    return redirect(url_for('protocols.index', server_id=server_id))


@bp.route('/<int:protocol_id>/restart', methods=['POST'])
@login_required
def restart(server_id, protocol_id):
    """Перезапуск контейнера с протоколом"""
    protocol = ServerProtocol.query.get_or_404(protocol_id)
    if protocol.server_id != server_id:
        abort(404)

    restart_protocol_task.delay(protocol.id)
    flash(f'Задача перезапуска протокола {protocol.protocol_type} добавлена в очередь.', 'info')

    return redirect(url_for('protocols.index', server_id=server_id))