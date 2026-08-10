from flask import render_template, redirect, url_for, flash, request, abort, jsonify
from flask_login import login_required
from app.clients import bp
from app.clients.forms import ClientForm
from app.clients.utils import generate_client_config, apply_client_to_server, generate_xray_keys, generate_wg_keys, \
    remove_client_from_server, get_next_client_ip, generate_wg_psk, generate_keys_for_client
from app.models import Client, Server, ServerProtocol
from app.extensions import db
from app.utils.crypto import encrypt_data, decrypt_data
from app.tasks import apply_client_task, remove_client_task
import json


@bp.route('/')
@login_required
def index():
    clients = Client.query.order_by(Client.created_at.desc()).all()
    return render_template('clients/index.html', clients=clients)


@bp.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = ClientForm()

    # Заполняем списки
    form.server_id.choices = [(0, '--- Выберите сервер ---')] + [(s.id, f"{s.name} ({s.ip})") for s in Server.query.order_by(Server.name).all()]
    
    protocols = ServerProtocol.query.filter_by(status='installed').order_by(ServerProtocol.protocol_type).all()
    form.protocol_id.choices = [(0, '--- Выберите протокол ---')] + [(p.id, f"{p.protocol_type.upper()} (сервер: {p.server.name})") for p in protocols]
    
    from app.models import ServerGroup
    form.group_id.choices = [(0, '--- Выберите группу ---')] + [(g.id, g.name) for g in ServerGroup.query.order_by(ServerGroup.name).all()]

    if form.validate_on_submit():
        client = Client(
            name=form.name.data,
            email=form.email.data,
            traffic_limit_bytes=int(form.traffic_limit.data) * 1024 ** 3 if form.traffic_limit.data else 0,
            expiry_date=form.expiry_date.data,
            status='pending'
        )

        if form.selection_type.data == 'server':
            if not form.server_id.data or form.server_id.data == 0:
                flash('Выберите сервер', 'danger')
                return render_template('clients/create.html', form=form)
            
            protocol = ServerProtocol.query.get(form.protocol_id.data)
            if not protocol or protocol.server_id != form.server_id.data:
                flash('Ошибка: выбранный протокол не соответствует серверу.', 'danger')
                return render_template('clients/create.html', form=form)
            
            client.server_id = form.server_id.data
            client.protocol_id = form.protocol_id.data
            client.protocol_type = protocol.protocol_type
        else:
            if not form.group_id.data or form.group_id.data == 0:
                flash('Выберите группу серверов', 'danger')
                return render_template('clients/create.html', form=form)
            
            client.group_id = form.group_id.data
            client.protocol_type = form.protocol_type.data

        db.session.add(client)
        db.session.commit()

        # Генерируем ключи
        _generate_keys_internal(client)
        
        # Запускаем применение асинхронно
        apply_client_task.delay(client.id)
        
        flash(f'Клиент {client.name} создан и отправлен на установку.', 'success')
        return redirect(url_for('clients.view', id=client.id))

    return render_template('clients/create.html', form=form)


def _generate_keys_internal(client):
    """Внутренняя функция генерации ключей (без редиректов и flash)"""
    # Раньше здесь лежала своя копия логики, которая для группового клиента брала
    # «эталонный» первый сервер группы и считала IP только по прямым клиентам этого
    # сервера — из-за чего адреса пересекались с клиентами группы. Используем общую
    # реализацию, где IP выдаётся по всем клиентам на том же интерфейсе.
    generate_keys_for_client(client)


@bp.route('/<int:id>')
@login_required
def view(id):
    client = Client.query.get_or_404(id)
    return render_template('clients/view.html', client=client)


@bp.route('/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    client = Client.query.get_or_404(id)
    form = ClientForm(obj=client)

    # Заполняем списки
    form.server_id.choices = [(s.id, f"{s.name} ({s.ip})") for s in Server.query.order_by(Server.name).all()]
    protocols = ServerProtocol.query.filter_by(status='installed').order_by(ServerProtocol.protocol_type).all()
    form.protocol_id.choices = [(p.id, f"{p.protocol_type.upper()} (сервер: {p.server.name})") for p in protocols]

    if form.validate_on_submit():
        # Проверяем соответствие сервера и протокола
        protocol = ServerProtocol.query.get(form.protocol_id.data)
        if protocol.server_id != form.server_id.data:
            flash('Ошибка: выбранный протокол не соответствует серверу.', 'danger')
            return redirect(url_for('clients.edit', id=id))

        client.name = form.name.data
        client.email = form.email.data
        client.server_id = form.server_id.data
        client.protocol_id = form.protocol_id.data
        client.traffic_limit_bytes = int(form.traffic_limit.data) * 1024 ** 3 if form.traffic_limit.data else 0
        client.expiry_date = form.expiry_date.data

        db.session.commit()
        flash('Данные клиента обновлены. Чтобы применить изменения на сервере, нажмите "Применить".', 'info')
        return redirect(url_for('clients.view', id=id))

    # Предзаполняем форму
    form.traffic_limit.data = client.traffic_limit_bytes // 1024 ** 3 if client.traffic_limit_bytes else 0
    return render_template('clients/edit.html', form=form, client=client)


@bp.route('/<int:id>/delete', methods=['POST'])
@login_required
def delete(id):
    client = Client.query.get_or_404(id)
    # Запускаем удаление асинхронно
    remove_client_task.delay(client.id)
    flash(f'Запущено удаление клиента {client.name} с сервера.', 'info')
    return redirect(url_for('clients.index'))


@bp.route('/<int:id>/generate-keys', methods=['POST'])
@login_required
def generate_keys(id):
    client = Client.query.get_or_404(id)
    try:
        _generate_keys_internal(client)
        flash('Ключи успешно сгенерированы.', 'success')
    except Exception as e:
        flash(f'Ошибка генерации ключей: {str(e)}', 'danger')
    
    return redirect(url_for('clients.view', id=client.id))


@bp.route('/<int:id>/apply', methods=['POST'])
@login_required
def apply_to_server(id):
    client = Client.query.get_or_404(id)

    # Определяем тип протокола универсально
    proto_type = client.protocol_type
    if not proto_type and client.protocol:
        proto_type = client.protocol.protocol_type

    # Проверяем наличие необходимых ключей
    if proto_type == 'awg' and not client.public_key:
        flash('Сначала сгенерируйте ключи.', 'warning')
        return redirect(url_for('clients.view', id=id))
    if proto_type == 'xray' and (not client.extra_params or 'uuid' not in client.extra_params):
        flash('Сначала сгенерируйте UUID.', 'warning')
        return redirect(url_for('clients.view', id=id))

    # Запускаем асинхронно
    apply_client_task.delay(client.id)
    flash(f'Задача применения клиента {client.name} отправлена в очередь.', 'info')

    return redirect(url_for('clients.view', id=client.id))


@bp.route('/<int:id>/config')
@login_required
def download_config(id):
    from flask import Response, current_app
    client = Client.query.get_or_404(id)

    try:
        config = generate_client_config(client)
    except Exception as e:
        import traceback
        current_app.logger.error(f"download_config error for client {id}: {e}\n{traceback.format_exc()}")
        flash(f'Ошибка генерации конфига: {e}', 'danger')
        return redirect(url_for('clients.view', id=id))

    if not config:
        flash('Не удалось сгенерировать конфиг. Убедитесь, что клиент активен, ключи сгенерированы и сервер/группа доступны.', 'danger')
        return redirect(url_for('clients.view', id=id))

    from urllib.parse import quote
    filename = f"{client.name}.conf"
    filename_encoded = quote(filename, safe='')
    return Response(
        config,
        mimetype='text/plain',
        headers={'Content-Disposition': f"attachment; filename*=UTF-8''{filename_encoded}"}
    )


@bp.route('/<int:id>/config-text')
@login_required
def config_text(id):
    from flask import Response, current_app
    from app.clients.utils import generate_amnezia_export_json, resolve_client_endpoint
    client = Client.query.get_or_404(id)
    proto_type = client.protocol_type or (client.protocol.protocol_type if client.protocol else None)

    try:
        if proto_type == 'awg':
            connection_address, connection_port = resolve_client_endpoint(client)
            if not connection_address or not connection_port:
                current_app.logger.warning(f"config_text: no endpoint for client {client.id}")
                abort(404)
            text = generate_amnezia_export_json(client, connection_address, connection_port)
        else:
            text = generate_client_config(client)
    except Exception as e:
        import traceback
        current_app.logger.error(f"config_text error for client {id}: {e}\n{traceback.format_exc()}")
        abort(500)

    if not text:
        abort(404)
    return Response(text, mimetype='text/plain')


@bp.route('/api/servers/<int:server_id>/protocols')
@login_required
def api_server_protocols(server_id):
    protocols = ServerProtocol.query.filter_by(server_id=server_id, status='installed').all()
    return jsonify([{
        'id': p.id,
        'protocol_type': p.protocol_type,
        'port': p.port
    } for p in protocols])