from flask import request, jsonify
from app.api import bp
from app.api.auth import token_required
from app.models import HaproxyServer, HaproxyBackend
from app.haproxy.manager import HaproxyManager

@bp.route('/haproxy/servers', methods=['GET'])
@token_required
def get_haproxy_servers():
    """
        Получить список HAProxy серверов
        ---
        tags:
          - haproxy
        security:
          - Bearer: []
        responses:
          200:
            description: Список HAProxy серверов
            schema:
              type: array
              items:
                type: object
                properties:
                  id:
                    type: integer
                    example: 1
                  name:
                    type: string
                    example: "haproxy-01"
                  ip:
                    type: string
                    example: "192.168.1.200"
                  status:
                    type: string
                    enum: [active, offline]
                    example: "active"
          401:
            description: Ошибка аутентификации
        """
    servers = HaproxyServer.query.all()
    return jsonify([{
        'id': s.id,
        'name': s.name,
        'ip': s.ip,
        'status': s.status
    } for s in servers])

@bp.route('/haproxy/servers/<int:id>/status', methods=['GET'])
@token_required
def get_haproxy_status(id):
    """
        Получить статус HAProxy сервера
        ---
        tags:
          - haproxy
        security:
          - Bearer: []
        parameters:
          - name: id
            in: path
            type: integer
            required: true
            description: ID HAProxy сервера
            example: 1
        responses:
          200:
            description: Информация о состоянии HAProxy
            schema:
              type: object
              additionalProperties:
                type: string
              example:
                Name: "haproxy-01"
                Version: "2.4.0"
                Uptime: "5d 12h 30m"
                Tasks: "10"
          401:
            description: Ошибка аутентификации
          404:
            description: Сервер не найден
        """
    server = HaproxyServer.query.get_or_404(id)
    manager = HaproxyManager(server)
    # Получаем статистику из сокета
    _, stats, _ = manager._execute_socket_command('show info')
    # Парсим простыню в dict
    info = {}
    for line in stats.split('\n'):
        if ':' in line:
            k, v = line.split(':', 1)
            info[k.strip()] = v.strip()
    return jsonify(info)

@bp.route('/haproxy/backends/<int:backend_id>/enable', methods=['POST'])
@token_required
def enable_backend(backend_id):
    """
        Включить все серверы в бэкенде
        ---
        tags:
          - haproxy
        security:
          - Bearer: []
        parameters:
          - name: backend_id
            in: path
            type: integer
            required: true
            description: ID бэкенда
            example: 1
        responses:
          200:
            description: Серверы включены
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "All servers enabled"
          401:
            description: Ошибка аутентификации
          404:
            description: Бэкенд не найден
        """
    backend = HaproxyBackend.query.get_or_404(backend_id)
    server = HaproxyServer.query.get(backend.haproxy_server_id)
    manager = HaproxyManager(server)
    for srv in backend.servers_json:
        manager.enable_server(backend.name, srv['name'])
    return jsonify({'message': 'All servers enabled'})

@bp.route('/haproxy/backends/<int:backend_id>/disable', methods=['POST'])
@token_required
def disable_backend(backend_id):
    """
        Отключить все серверы в бэкенде
        ---
        tags:
          - haproxy
        security:
          - Bearer: []
        parameters:
          - name: backend_id
            in: path
            type: integer
            required: true
            description: ID бэкенда
            example: 1
        responses:
          200:
            description: Серверы отключены
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "All servers disabled"
          401:
            description: Ошибка аутентификации
          404:
            description: Бэкенд не найден
        """
    backend = HaproxyBackend.query.get_or_404(backend_id)
    server = HaproxyServer.query.get(backend.haproxy_server_id)
    manager = HaproxyManager(server)
    for srv in backend.servers_json:
        manager.disable_server(backend.name, srv['name'])
    return jsonify({'message': 'All servers disabled'})