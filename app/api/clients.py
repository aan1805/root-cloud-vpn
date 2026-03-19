from flask import request, jsonify, url_for
from app.api import bp
from app.api.auth import token_required
from app.models import Client, Server, ServerProtocol
from app.extensions import db
from app.clients.utils import generate_wg_keys, generate_xray_keys, apply_client_to_server, generate_client_config
from app.utils.crypto import encrypt_data
from datetime import datetime


@bp.route('/clients', methods=['GET'])
@token_required
def get_clients():
    """
        Получить список всех клиентов
        ---
        tags:
          - clients
        security:
          - Bearer: []
        responses:
          200:
            description: Список клиентов
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                    description: ID клиента
                    example: 1
                  name:
                    type: string
                    description: Имя клиента
                    example: "Иван Иванов"
                  email:
                    type: string
                    description: Email клиента
                    example: "ivan@example.com"
                  server_id:
                    type: integer
                    description: ID сервера
                    example: 1
                  protocol_id:
                    type: integer
                    description: ID протокола
                    example: 1
                  status:
                    type: string
                    description: Статус клиента
                    enum: [active, blocked, expired]
                    example: "active"
                  traffic_used_mb:
                    type: number
                    description: Использовано трафика в МБ
                    example: 1024.5
                  traffic_limit_mb:
                    type: number
                    description: Лимит трафика в МБ
                    example: 10240
                  expiry_date:
                    type: string
                    format: date-time
                    description: Дата истечения подписки
                    example: "2024-12-31T23:59:59"
                  created_at:
                    type: string
                    format: date-time
                    description: Дата создания
                    example: "2024-01-01T10:00:00"
          401:
            description: Ошибка аутентификации
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Token is missing"
        """
    limit = request.args.get('limit', type=int)
    status = request.args.get('status')
    server_id = request.args.get('server_id', type=int)

    # Базовый запрос
    query = Client.query

    # Фильтры
    if status:
        query = query.filter_by(status=status)
    if server_id:
        query = query.filter_by(server_id=server_id)

    # Сортировка и лимит
    query = query.order_by(Client.created_at.desc())
    if limit:
        query = query.limit(limit)

    clients = query.all()

    return jsonify([{
        'id': c.id,
        'name': c.name,
        'email': c.email,
        'server_id': c.server_id,
        'protocol_id': c.protocol_id,
        'status': c.status,
        'traffic_used_mb': c.traffic_used_bytes / (1024 * 1024) if c.traffic_used_bytes else 0,
        'traffic_limit_mb': c.traffic_limit_bytes / (1024 * 1024) if c.traffic_limit_bytes else 0,
        'expiry_date': c.expiry_date.isoformat() if c.expiry_date else None,
        'created_at': c.created_at.isoformat()
    } for c in clients])


@bp.route('/clients', methods=['POST'])
@token_required
def create_client():
    """
        Создать нового клиента
        ---
        tags:
          - clients
        security:
          - Bearer: []
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              required:
                - name
                - server_id
                - protocol_id
              properties:
                name:
                  type: string
                  description: Имя клиента
                  example: "Петр Петров"
                email:
                  type: string
                  description: Email клиента
                  example: "petr@example.com"
                server_id:
                  type: integer
                  description: ID сервера
                  example: 1
                protocol_id:
                  type: integer
                  description: ID протокола
                  example: 1
                traffic_limit_gb:
                  type: integer
                  description: Лимит трафика в ГБ
                  example: 10
                expiry_date:
                  type: string
                  format: date-time
                  description: Дата истечения подписки
                  example: "2024-12-31T23:59:59"
        responses:
          201:
            description: Клиент успешно создан
            schema:
              type: object
              properties:
                id:
                  type: integer
                  example: 1
                message:
                  type: string
                  example: "Client created"
          400:
            description: Ошибка валидации
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Missing field: name"
          401:
            description: Ошибка аутентификации
          404:
            description: Сервер или протокол не найден
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Server not found"
          500:
            description: Ошибка генерации ключей
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Key generation failed: ..."
        """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    required = ['name', 'server_id', 'protocol_id']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400

    # Проверяем существование сервера и протокола
    server = Server.query.get(data['server_id'])
    if not server:
        return jsonify({'error': 'Server not found'}), 404
    protocol = ServerProtocol.query.get(data['protocol_id'])
    if not protocol or protocol.server_id != server.id:
        return jsonify({'error': 'Protocol not found or does not belong to server'}), 400

    # Создаём клиента
    client = Client(
        name=data['name'],
        email=data.get('email'),
        server_id=server.id,
        protocol_id=protocol.id,
        traffic_limit_bytes=int(data.get('traffic_limit_gb', 0)) * 1024 ** 3,
        expiry_date=datetime.fromisoformat(data['expiry_date']) if data.get('expiry_date') else None,
        status='active'
    )

    # Генерируем ключи в зависимости от протокола
    if protocol.protocol_type == 'awg':
        try:
            private_key, public_key = generate_wg_keys()
            client.public_key = public_key
            client.private_key_encrypted = encrypt_data(private_key)
        except Exception as e:
            return jsonify({'error': f'Key generation failed: {str(e)}'}), 500
    elif protocol.protocol_type == 'xray':
        uuid_val = generate_xray_keys()
        client.extra_params = {'uuid': uuid_val, 'email': data.get('email', client.name)}

    db.session.add(client)
    db.session.commit()

    # Применяем на сервере (опционально, можно сделать фоновую задачу)
    try:
        apply_client_to_server(client)
    except Exception as e:
        # Логируем, но не откатываем транзакцию
        pass

    return jsonify({'id': client.id, 'message': 'Client created'}), 201


@bp.route('/clients/<int:id>/config', methods=['GET'])
@token_required
def get_client_config(id):
    """
        Получить конфигурацию клиента
        ---
        tags:
          - clients
        security:
          - Bearer: []
        parameters:
          - name: id
            in: path
            type: integer
            required: true
            description: ID клиента
            example: 1
        responses:
          200:
            description: Конфигурация клиента
            schema:
              type: object
              properties:
                client_id:
                  type: integer
                  example: 1
                config:
                  type: string
                  description: Конфигурация в формате WireGuard или VLESS
                  example: "[Interface]\nPrivateKey = ..."
                format:
                  type: string
                  enum: [conf, vless]
                  example: "conf"
          401:
            description: Ошибка аутентификации
          404:
            description: Клиент не найден
          500:
            description: Ошибка генерации конфигурации
        """
    client = Client.query.get_or_404(id)
    config = generate_client_config(client)
    if not config:
        return jsonify({'error': 'Could not generate config'}), 500

    return jsonify({
        'client_id': client.id,
        'config': config,
        'format': 'conf' if client.protocol.protocol_type == 'awg' else 'vless'
    })


@bp.route('/clients/<int:id>/block', methods=['POST'])
@token_required
def block_client(id):
    """
        Заблокировать клиента
        ---
        tags:
          - clients
        security:
          - Bearer: []
        parameters:
          - name: id
            in: path
            type: integer
            required: true
            description: ID клиента
            example: 1
        responses:
          200:
            description: Клиент заблокирован
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "Client blocked"
          401:
            description: Ошибка аутентификации
          404:
            description: Клиент не найден
        """
    client = Client.query.get_or_404(id)
    client.status = 'blocked'
    db.session.commit()
    # Удалить с сервера через фоновую задачу
    return jsonify({'message': 'Client blocked'})


@bp.route('/clients/<int:id>/unblock', methods=['POST'])
@token_required
def unblock_client(id):
    """
        Разблокировать клиента
        ---
        tags:
          - clients
        security:
          - Bearer: []
        parameters:
          - name: id
            in: path
            type: integer
            required: true
            description: ID клиента
            example: 1
        responses:
          200:
            description: Клиент разблокирован
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "Client unblocked"
          401:
            description: Ошибка аутентификации
          404:
            description: Клиент не найден
        """
    client = Client.query.get_or_404(id)
    client.status = 'active'
    db.session.commit()
    # Переприменить на сервере
    return jsonify({'message': 'Client unblocked'})