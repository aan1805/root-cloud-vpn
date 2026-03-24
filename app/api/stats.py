from flask import request, jsonify
from sqlalchemy import func

from app import db
from app.api import bp
from app.api.auth import token_required
from app.models import TrafficStats, ServerStats, HaproxyStats, Client, Server, HaproxyServer
from datetime import datetime, timedelta, date


@bp.route('/stats/traffic/client/<int:client_id>', methods=['GET'])
@token_required
def client_traffic_stats(client_id):
    """Возвращает статистику трафика по дням для клиента"""
    client = Client.query.get_or_404(client_id)

    # Параметры: days (сколько дней вернуть, по умолчанию 30)
    days = request.args.get('days', 30, type=int)
    start_date = date.today() - timedelta(days=days)

    stats = TrafficStats.query.filter(
        TrafficStats.client_id == client_id,
        TrafficStats.date >= start_date
    ).order_by(TrafficStats.date).all()

    result = {
        'client_id': client_id,
        'client_name': client.name,
        'data': [{
            'date': s.date.isoformat(),
            'bytes_sent': s.bytes_sent,
            'bytes_received': s.bytes_received,
            'total_bytes': s.bytes_sent + s.bytes_received
        } for s in stats]
    }

    return jsonify(result)


@bp.route('/stats/traffic/server/<int:server_id>', methods=['GET'])
@token_required
def server_traffic_stats(server_id):
    """Суммарный трафик по серверу (все клиенты)"""
    server = Server.query.get_or_404(server_id)

    days = request.args.get('days', 30, type=int)
    start_date = date.today() - timedelta(days=days)

    # Получаем всех клиентов сервера
    client_ids = [c.id for c in server.clients]

    if not client_ids:
        return jsonify({'data': []})

    # Группируем по датам
    from sqlalchemy import func
    stats = db.session.query(
        TrafficStats.date,
        func.sum(TrafficStats.bytes_sent).label('total_sent'),
        func.sum(TrafficStats.bytes_received).label('total_received')
    ).filter(
        TrafficStats.client_id.in_(client_ids),
        TrafficStats.date >= start_date
    ).group_by(TrafficStats.date).order_by(TrafficStats.date).all()

    result = {
        'server_id': server_id,
        'server_name': server.name,
        'data': [{
            'date': s.date.isoformat(),
            'bytes_sent': s.total_sent,
            'bytes_received': s.total_received,
            'total_bytes': s.total_sent + s.total_received
        } for s in stats]
    }

    return jsonify(result)


@bp.route('/stats/traffic/server/all', methods=['GET'])
@token_required
def all_servers_traffic_stats():
    """Суммарный трафик по всем серверам (все клиенты)"""
    days = request.args.get('days', 30, type=int)
    start_date = date.today() - timedelta(days=days)

    # Группируем по датам
    from sqlalchemy import func
    stats = db.session.query(
        TrafficStats.date,
        func.sum(TrafficStats.bytes_sent).label('total_sent'),
        func.sum(TrafficStats.bytes_received).label('total_received')
    ).filter(
        TrafficStats.date >= start_date
    ).group_by(TrafficStats.date).order_by(TrafficStats.date).all()

    result = {
        'data': [{
            'date': s.date.isoformat(),
            'bytes_sent': s.total_sent,
            'bytes_received': s.total_received,
            'total_bytes': s.total_sent + s.total_received
        } for s in stats]
    }

    return jsonify(result)


@bp.route('/stats/server/<int:server_id>/resources', methods=['GET'])
@token_required
def server_resources_stats(server_id):
    """Статистика использования ресурсов сервера (CPU, RAM, сеть)"""
    server = Server.query.get_or_404(server_id)

    hours = request.args.get('hours', 24, type=int)
    start_time = datetime.utcnow() - timedelta(hours=hours)

    stats = ServerStats.query.filter(
        ServerStats.server_id == server_id,
        ServerStats.timestamp >= start_time
    ).order_by(ServerStats.timestamp).all()

    result = {
        'server_id': server_id,
        'server_name': server.name,
        'data': [{
            'timestamp': s.timestamp.isoformat(),
            'cpu_usage': s.cpu_usage,
            'memory_usage': s.memory_usage,
            'load_1min': s.load_1min,
            'net_in_bytes': s.net_in_bytes,
            'net_out_bytes': s.net_out_bytes,
        } for s in stats]
    }

    return jsonify(result)


@bp.route('/stats/servers/resources/latest', methods=['GET'])
@token_required
def all_servers_resources_latest():
    """Последние показатели ресурсов всех VPN-серверов (для дашборда)"""
    servers = Server.query.all()
    result = []
    for server in servers:
        stat = ServerStats.query.filter_by(server_id=server.id) \
            .order_by(ServerStats.timestamp.desc()).first()
        result.append({
            'server_id': server.id,
            'server_name': server.name,
            'status': server.status,
            'fornex_vps_id': server.fornex_vps_id,
            'cpu_usage': stat.cpu_usage if stat else None,
            'memory_usage': stat.memory_usage if stat else None,
            'load_1min': stat.load_1min if stat else None,
            'net_in_bytes': stat.net_in_bytes if stat else None,
            'net_out_bytes': stat.net_out_bytes if stat else None,
            'last_update': stat.timestamp.isoformat() if stat else None,
        })
    return jsonify(result)


@bp.route('/stats/haproxy/resources/latest', methods=['GET'])
@token_required
def all_haproxy_resources_latest():
    """Последние показатели ресурсов балансировщиков HAProxy"""
    haproxy_servers = HaproxyServer.query.all()
    result = []
    for hap in haproxy_servers:
        stat = HaproxyStats.query.filter_by(haproxy_server_id=hap.id) \
            .order_by(HaproxyStats.timestamp.desc()).first()
        result.append({
            'haproxy_id': hap.id,
            'haproxy_name': hap.name,
            'fornex_vps_id': hap.fornex_vps_id,
            'cpu_usage': stat.cpu_usage if stat else None,
            'memory_usage': stat.memory_usage if stat else None,
            'load_1min': stat.load_1min if stat else None,
            'net_in_bytes': stat.net_in_bytes if stat else None,
            'net_out_bytes': stat.net_out_bytes if stat else None,
            'last_update': stat.timestamp.isoformat() if stat else None,
        })
    return jsonify(result)


@bp.route('/stats/dashboard', methods=['GET'])
@token_required
def dashboard_summary():
    """Сводная информация для главной страницы"""
    # Общая статистика
    total_servers = Server.query.count()
    online_servers = Server.query.filter_by(status='online').count()
    total_clients = Client.query.count()
    active_clients = Client.query.filter_by(status='active').count()

    # Трафик за сегодня
    today = date.today()
    traffic_today = db.session.query(
        func.sum(TrafficStats.bytes_sent + TrafficStats.bytes_received)
    ).filter(TrafficStats.date == today).scalar() or 0

    # Трафик за месяц
    month_start = date.today().replace(day=1)
    traffic_month = db.session.query(
        func.sum(TrafficStats.bytes_sent + TrafficStats.bytes_received)
    ).filter(TrafficStats.date >= month_start).scalar() or 0

    traffic_today = int(traffic_today)
    traffic_month = int(traffic_month)

    return jsonify({
        'servers': {
            'total': total_servers,
            'online': online_servers,
            'offline': total_servers - online_servers
        },
        'clients': {
            'total': total_clients,
            'active': active_clients,
            'blocked': Client.query.filter_by(status='blocked').count(),
            'expired': Client.query.filter_by(status='expired').count()
        },
        'traffic': {
            'today_bytes': traffic_today,
            'today_mb': traffic_today / (1024 * 1024),
            'month_bytes': traffic_month,
            'month_gb': traffic_month / (1024 ** 3)
        }
    })