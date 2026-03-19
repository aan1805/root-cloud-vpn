from flask import request, jsonify
from app.api import bp
from app.api.auth import token_required
from app.models import Server, ServerProtocol
from app.extensions import db
from app.servers.ssh import test_ssh_connection
from app.utils.crypto import encrypt_data


@bp.route('/servers', methods=['GET'])
@token_required
def get_servers():
    """
    Получить список всех серверов
    ---
    tags:
      - servers
    security:
      - Bearer: []
    responses:
      200:
        description: Список серверов
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
                description: ID сервера
                example: 1
              name:
                type: string
                description: Название сервера
                example: "Main Server"
              ip:
                type: string
                description: IP адрес
                example: "192.168.1.100"
              status:
                type: string
                description: Статус сервера
                enum: [active, offline, maintenance]
                example: "active"
              created_at:
                type: string
                format: date-time
                description: Дата создания
                example: "2024-01-01T12:00:00"
      401:
        description: Ошибка аутентификации
    """
    servers = Server.query.all()
    return jsonify([{
        'id': s.id,
        'name': s.name,
        'ip': s.ip,
        'status': s.status,
        'created_at': s.created_at.isoformat()
    } for s in servers])


@bp.route('/servers', methods=['POST'])
@token_required
def create_server():
    """
        Создать новый сервер
        ---
        tags:
          - servers
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
                - ip
                - ssh_username
                - ssh_key
              properties:
                name:
                  type: string
                  description: Название сервера
                  example: "VPN Server 1"
                ip:
                  type: string
                  description: IP адрес сервера
                  example: "192.168.1.100"
                ssh_port:
                  type: integer
                  description: SSH порт
                  default: 22
                  example: 22
                ssh_username:
                  type: string
                  description: Имя пользователя SSH
                  example: "root"
                ssh_key:
                  type: string
                  description: Приватный SSH ключ (будет зашифрован)
                  example: "-----BEGIN RSA PRIVATE KEY-----\n..."
                ssh_key_passphrase:
                  type: string
                  description: Парольная фраза для SSH ключа (опционально)
                  example: "my_passphrase"
        responses:
          201:
            description: Сервер успешно создан
            schema:
              type: object
              properties:
                id:
                  type: integer
                  example: 1
                message:
                  type: string
                  example: "Server created"
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
        """
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Валидация
    required = ['name', 'ip', 'ssh_username', 'ssh_key']
    for field in required:
        if field not in data:
            return jsonify({'error': f'Missing field: {field}'}), 400

    # Шифруем ключи
    encrypted_key = encrypt_data(data['ssh_key'])
    encrypted_passphrase = None
    if 'ssh_key_passphrase' in data:
        encrypted_passphrase = encrypt_data(data['ssh_key_passphrase'])

    server = Server(
        name=data['name'],
        ip=data['ip'],
        ssh_port=data.get('ssh_port', 22),
        ssh_username=data['ssh_username'],
        ssh_key_encrypted=encrypted_key,
        ssh_key_passphrase_encrypted=encrypted_passphrase,
        status='offline'
    )
    db.session.add(server)
    db.session.commit()

    return jsonify({'id': server.id, 'message': 'Server created'}), 201


@bp.route('/servers/<int:id>', methods=['GET'])
@token_required
def get_server(id):
    """
        Получить информацию о сервере
        ---
        tags:
          - servers
        security:
          - Bearer: []
        parameters:
          - name: id
            in: path
            type: integer
            required: true
            description: ID сервера
            example: 1
        responses:
          200:
            description: Информация о сервере
            schema:
              type: object
              properties:
                id:
                  type: integer
                  example: 1
                name:
                  type: string
                  example: "Main Server"
                ip:
                  type: string
                  example: "192.168.1.100"
                ssh_port:
                  type: integer
                  example: 22
                status:
                  type: string
                  example: "active"
                created_at:
                  type: string
                  format: date-time
                  example: "2024-01-01T12:00:00"
          401:
            description: Ошибка аутентификации
          404:
            description: Сервер не найден
        """
    server = Server.query.get_or_404(id)
    return jsonify({
        'id': server.id,
        'name': server.name,
        'ip': server.ip,
        'ssh_port': server.ssh_port,
        'status': server.status,
        'created_at': server.created_at.isoformat()
    })


@bp.route('/servers/<int:id>/check', methods=['POST'])
@token_required
def check_server(id):
    """
        Проверить доступность сервера по SSH
        ---
        tags:
          - servers
        security:
          - Bearer: []
        parameters:
          - name: id
            in: path
            type: integer
            required: true
            description: ID сервера
            example: 1
        responses:
          200:
            description: Результат проверки
            schema:
              type: object
              properties:
                success:
                  type: boolean
                  example: true
                message:
                  type: string
                  example: "SSH connection successful"
          401:
            description: Ошибка аутентификации
          404:
            description: Сервер не найден
        """
    server = Server.query.get_or_404(id)
    from app.servers.routes import check_server_connection
    success, message = check_server_connection(server)
    return jsonify({'success': success, 'message': message})


@bp.route('/servers/<int:id>/protocols', methods=['GET'])
@token_required
def get_server_protocols(id):
    """
        Получить список протоколов сервера
        ---
        tags:
          - servers
        security:
          - Bearer: []
        parameters:
          - name: id
            in: path
            type: integer
            required: true
            description: ID сервера
            example: 1
        responses:
          200:
            description: Список протоколов
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                    description: ID протокола
                    example: 1
                  protocol_type:
                    type: string
                    description: Тип протокола
                    enum: [awg, xray]
                    example: "awg"
                  port:
                    type: integer
                    description: Порт
                    example: 51820
                  status:
                    type: string
                    description: Статус протокола
                    example: "active"
                  config_params:
                    type: object
                    description: Дополнительные параметры конфигурации
                    example: {"mtu": 1420}
          401:
            description: Ошибка аутентификации
          404:
            description: Сервер не найден
        """
    server = Server.query.get_or_404(id)
    protocols = ServerProtocol.query.filter_by(server_id=server.id).all()
    return jsonify([{
        'id': p.id,
        'protocol_type': p.protocol_type,
        'port': p.port,
        'status': p.status,
        'config_params': p.config_params
    } for p in protocols])