from app.celery_app import celery
from app.models import Client, Server, ServerProtocol, ServerStats, TrafficStats, ApiToken, HaproxyServer, HaproxyStats, FornexSetting, ServerGroup
from app.extensions import db
from app.servers.ssh import execute_ssh_command
from app.utils.crypto import decrypt_data
from datetime import datetime, date, timedelta
from sqlalchemy import or_, and_
import logging
import re
import requests as http_requests

logger = logging.getLogger(__name__)


@celery.task(bind=True)
def collect_all_stats(self):
    """Собирает статистику со всех серверов"""
    servers = Server.query.filter_by(status='online').all()
    for server in servers:
        collect_server_stats.delay(server.id)
        collect_detailed_wg_stats.delay(server.id)
        collect_server_resources.delay(server.id)
    collect_fornex_stats.delay()
    return f"Запущен сбор статистики для {len(servers)} серверов"


@celery.task(bind=True)
def collect_server_stats(self, server_id):
    """Собирает статистику с конкретного сервера"""
    server = Server.query.get(server_id)
    if not server:
        return f"Сервер {server_id} не найден"

    # Расшифровываем ключи
    key = decrypt_data(server.ssh_key_encrypted)
    passphrase = decrypt_data(server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None

    # Собираем статистику для каждого протокола
    for protocol in server.protocols:
        if protocol.status != 'installed':
            continue

        if protocol.protocol_type == 'awg':
            collect_wg_stats(server, protocol, key, passphrase)
        elif protocol.protocol_type == 'xray':
            collect_xray_stats(server, protocol, key, passphrase)

    return f"Статистика для сервера {server.name} собрана"


def collect_wg_stats(server, protocol, ssh_key, passphrase):
    """Сбор статистики WireGuard"""
    # Получаем информацию о пирах через wg show
    command = "sudo awg show wg0 dump"
    exit_code, stdout, stderr = execute_ssh_command(
        server.ip, server.ssh_port, server.ssh_username,
        ssh_key, command, passphrase
    )

    if exit_code != 0:
        logger.error(f"Ошибка получения статистики WG: {stderr}")
        return

    # Парсим вывод wg dump
    # Формат: public_key, preshared_key, endpoint, allowed_ips, latest_handshake, transfer_rx, transfer_tx, persistent_keepalive
    lines = stdout.strip().split('\n')
    if not lines:
        return

    # Первая строка - интерфейс, остальные - пиры
    for line in lines[1:]:
        parts = line.split('\t')
        if len(parts) < 7:
            continue

        public_key = parts[0]
        transfer_rx = int(parts[5])  # получено байт
        transfer_tx = int(parts[6])  # отправлено байт

        # Находим клиента с таким публичным ключом
        # Сначала ищем прямого клиента сервера
        client = Client.query.filter_by(
            server_id=server.id,
            protocol_id=protocol.id,
            public_key=public_key
        ).first()
        # Если не нашли — ищем группового клиента (server_id=NULL, привязан к группе сервера)
        if not client and server.group_id:
            client = Client.query.filter(
                Client.public_key == public_key,
                Client.group_id == server.group_id,
                Client.protocol_type == protocol.protocol_type
            ).first()

        if client:
            # Обновляем использованный трафик (сумма RX + TX)
            client.traffic_used_bytes = transfer_rx + transfer_tx
            logger.info(f"Клиент {client.name}: использовано {client.traffic_used_bytes} байт")

    db.session.commit()


def collect_xray_stats(server, protocol, ssh_key, passphrase):
    """Сбор статистики XRay (через API Xray)"""
    # Вызываем xray api для получения статистики
    command = "sudo docker exec xray-reality xray api statsquery --server=127.0.0.1:10085"
    exit_code, stdout, stderr = execute_ssh_command(
        server.ip, server.ssh_port, server.ssh_username,
        ssh_key, command, passphrase
    )

    if exit_code != 0:
        logger.error(f"Ошибка получения статистики XRay: {stderr}")
        return

    try:
        import json
        data = json.loads(stdout)
        stats = data.get('stat', [])
        
        # Группируем по email (названию клиента в xray)
        user_traffic = {}
        
        for item in stats:
            # Формат имени: user>>>email>>>traffic>>>downlink/uplink
            name_parts = item.get('name', '').split('>>>')
            if len(name_parts) >= 4 and name_parts[0] == 'user':
                email = name_parts[1]
                value = int(item.get('value', 0))
                
                if email not in user_traffic:
                    user_traffic[email] = 0
                user_traffic[email] += value

        # Обновляем клиентов в БД
        for email, total_bytes in user_traffic.items():
            # Ищем прямого клиента сервера
            client = Client.query.filter(
                Client.server_id == server.id,
                Client.protocol_id == protocol.id,
                (Client.email == email) | (Client.extra_params['email'].astext == email)
            ).first()
            # Групповой клиент (server_id=NULL)
            if not client and server.group_id:
                client = Client.query.filter(
                    Client.group_id == server.group_id,
                    Client.protocol_type == protocol.protocol_type,
                    (Client.email == email) | (Client.extra_params['email'].astext == email)
                ).first()

            if client:
                client.traffic_used_bytes = total_bytes
                logger.info(f"Клиент XRay {client.name} ({email}): использовано {total_bytes} байт")

        db.session.commit()
    except Exception as e:
        logger.error(f"Ошибка парсинга статистики XRay: {str(e)}")


@celery.task(bind=True)
def check_all_limits(self):
    """Проверяет лимиты всех клиентов и блокирует при необходимости"""
    clients = Client.query.filter_by(status='active').all()
    blocked_count = 0

    for client in clients:
        if check_client_limits(client):
            block_client(client)
            blocked_count += 1

    return f"Проверено {len(clients)} клиентов, заблокировано {blocked_count}"


def check_client_limits(client):
    """Проверяет лимиты клиента, возвращает True если нужно заблокировать"""
    now = datetime.utcnow()

    # Проверка срока действия
    if client.expiry_date and client.expiry_date < now:
        logger.info(f"Клиент {client.name} просрочен")
        return True

    # Проверка лимита трафика
    if client.traffic_limit_bytes > 0 and client.traffic_used_bytes >= client.traffic_limit_bytes:
        logger.info(f"Клиент {client.name} превысил лимит трафика")
        return True

    return False


def block_client(client):
    """Блокирует клиента на сервере"""
    # Используем асинхронную задачу для удаления
    from app.tasks import remove_client_task
    client.status = 'blocked'
    db.session.commit()

    # Удаляем клиента с сервера асинхронно
    remove_client_task.delay(client.id, delete_from_db=False)


@celery.task(bind=True)
def check_server_status(self, server_id):
    """Проверяет доступность сервера по SSH"""
    server = Server.query.get(server_id)
    if not server:
        return

    key = decrypt_data(server.ssh_key_encrypted)
    passphrase = decrypt_data(server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None

    command = "echo OK"
    exit_code, stdout, stderr = execute_ssh_command(
        server.ip, server.ssh_port, server.ssh_username,
        key, command, passphrase
    )

    old_status = server.status
    server.status = 'online' if exit_code == 0 else 'offline'

    if old_status != server.status:
        logger.info(f"Статус сервера {server.name} изменён: {old_status} -> {server.status}")

    db.session.commit()
    return server.status


@celery.task(bind=True)
def check_all_servers_status(self):
    """Проверяет статус всех серверов"""
    servers = Server.query.all()
    for server in servers:
        check_server_status.delay(server.id)
    return f"Запущена проверка {len(servers)} серверов"


@celery.task(bind=True)
def collect_detailed_wg_stats(self, server_id):
    """Собирает детальную статистику по каждому клиенту WireGuard"""
    server = Server.query.get(server_id)
    if not server:
        return

    key = decrypt_data(server.ssh_key_encrypted)
    passphrase = decrypt_data(server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None

    for protocol in server.protocols:
        if protocol.protocol_type != 'awg' or protocol.status != 'installed':
            continue

        # Получаем статистику по пирам
        command = "sudo awg show wg0 transfer"
        exit_code, stdout, stderr = execute_ssh_command(
            server.ip, server.ssh_port, server.ssh_username,
            key, command, passphrase
        )

        if exit_code != 0:
            continue

        # Парсим вывод: каждая строка: public_key rx_bytes tx_bytes
        for line in stdout.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 3:
                public_key = parts[0]
                rx_bytes = int(parts[1])
                tx_bytes = int(parts[2])

                client = Client.query.filter_by(
                    server_id=server.id,
                    protocol_id=protocol.id,
                    public_key=public_key
                ).first()
                if not client and server.group_id:
                    client = Client.query.filter(
                        Client.public_key == public_key,
                        Client.group_id == server.group_id,
                        Client.protocol_type == protocol.protocol_type
                    ).first()

                if client:
                    # Сохраняем статистику за сегодня
                    # rx_bytes/tx_bytes — накопительные счётчики WireGuard (с момента старта интерфейса),
                    # поэтому сохраняем дельту (разницу с предыдущим днём), а не абсолютное значение
                    today = date.today()
                    stats = TrafficStats.query.filter_by(
                        client_id=client.id,
                        date=today
                    ).first()

                    # Находим предыдущий накопительный baseline (последняя запись до сегодня)
                    prev_stats = TrafficStats.query.filter(
                        TrafficStats.client_id == client.id,
                        TrafficStats.date < today
                    ).order_by(TrafficStats.date.desc()).first()

                    baseline_rx = prev_stats.cumulative_rx if prev_stats else rx_bytes
                    baseline_tx = prev_stats.cumulative_tx if prev_stats else tx_bytes

                    # Дельта за день (защита от сброса счётчика при перезапуске WG)
                    delta_rx = max(0, rx_bytes - baseline_rx)
                    delta_tx = max(0, tx_bytes - baseline_tx)

                    if not stats:
                        stats = TrafficStats(
                            client_id=client.id,
                            date=today,
                            bytes_received=delta_rx,
                            bytes_sent=delta_tx,
                            cumulative_rx=rx_bytes,
                            cumulative_tx=tx_bytes
                        )
                        db.session.add(stats)
                    else:
                        stats.bytes_received = delta_rx
                        stats.bytes_sent = delta_tx
                        stats.cumulative_rx = rx_bytes
                        stats.cumulative_tx = tx_bytes

                    # Обновляем общий счётчик у клиента
                    client.traffic_used_bytes = rx_bytes + tx_bytes

        db.session.commit()


@celery.task(bind=True)
def collect_server_resources(self, server_id):
    """Собирает информацию о ресурсах сервера (CPU, RAM)"""
    server = Server.query.get(server_id)
    if not server:
        return

    key = decrypt_data(server.ssh_key_encrypted)
    passphrase = decrypt_data(server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None

    # Получаем информацию о CPU
    cpu_command = "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1"
    exit_code, cpu_out, _ = execute_ssh_command(
        server.ip, server.ssh_port, server.ssh_username,
        key, cpu_command, passphrase
    )

    # Получаем информацию о памяти
    mem_command = "free | grep Mem | awk '{print $3/$2 * 100.0}'"
    exit_code, mem_out, _ = execute_ssh_command(
        server.ip, server.ssh_port, server.ssh_username,
        key, mem_command, passphrase
    )

    # Получаем load average
    load_command = "cat /proc/loadavg | awk '{print $1}'"
    exit_code, load_out, _ = execute_ssh_command(
        server.ip, server.ssh_port, server.ssh_username,
        key, load_command, passphrase
    )

    try:
        cpu_usage = float(cpu_out.strip()) if cpu_out.strip() else None
        memory_usage = float(mem_out.strip()) if mem_out.strip() else None
        load_1min = float(load_out.strip()) if load_out.strip() else None

        stats = ServerStats(
            server_id=server.id,
            cpu_usage=cpu_usage,
            memory_usage=memory_usage,
            load_1min=load_1min
        )
        db.session.add(stats)
        db.session.commit()
    except ValueError:
        pass


def _fetch_fornex_field(base_url, order_id, field, headers):
    """
    Запрашивает одно поле статистики: GET {base_url}/vps/{order_id}/stats/{field}/
    Возвращает float/int или None при ошибке.

    Ответ API может быть числом, строкой или объектом {"value": ...}.
    """
    url = f"{base_url}/vps/{order_id}/stats/{field}/"
    try:
        resp = http_requests.get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            return None
        data = resp.json()
        # Если вернули объект — берём поле value
        if isinstance(data, dict):
            val = data.get('value') or data.get(field) or data.get('data')
        else:
            val = data
        return float(val) if val is not None else None
    except Exception:
        return None


def _collect_fornex_for(base_url, order_id, headers):
    """
    Собирает cpu, ram, net_rx, net_tx для одного order_id.
    Возвращает dict с ключами cpu, mem, net_in, net_out (могут быть None).
    """
    # Поля, которые пробуем для каждой метрики (по приоритету)
    cpu = _fetch_fornex_field(base_url, order_id, 'cpu', headers)

    mem = _fetch_fornex_field(base_url, order_id, 'ram', headers)
    if mem is None:
        mem = _fetch_fornex_field(base_url, order_id, 'mem', headers)

    net_in = _fetch_fornex_field(base_url, order_id, 'net_rx', headers)
    if net_in is None:
        net_in = _fetch_fornex_field(base_url, order_id, 'net_in', headers)

    net_out = _fetch_fornex_field(base_url, order_id, 'net_tx', headers)
    if net_out is None:
        net_out = _fetch_fornex_field(base_url, order_id, 'net_out', headers)

    return dict(cpu=cpu, mem=mem, net_in=net_in, net_out=net_out)


@celery.task(bind=True)
def collect_fornex_stats(self):
    """
    Собирает статистику серверов через Fornex API.
    Endpoint: GET {base_url}/vps/{order_id}/stats/{field}/
    Примеры полей: cpu, ram, net_rx, net_tx
    Auth: Authorization: Api-Key {key}

    Обновляет ServerStats для VPN-серверов и HaproxyStats для балансировщиков.
    """
    setting = FornexSetting.get()
    if not setting:
        logger.debug("Fornex API не настроен, пропускаем сбор статистики")
        return "Fornex не настроен"

    from app.utils.crypto import decrypt_data as _decrypt
    try:
        api_key = _decrypt(setting.api_key_encrypted)
    except Exception as e:
        logger.error(f"Ошибка расшифровки Fornex API ключа: {e}")
        return f"Ошибка ключа: {e}"

    base_url = (setting.api_base_url or 'https://fornex.com/api').rstrip('/')
    headers = {
        'Authorization': f'Api-Key {api_key}',
        'Accept': 'application/json',
    }

    collected = 0

    # VPN серверы
    servers = Server.query.filter(Server.fornex_vps_id.isnot(None)).all()
    for server in servers:
        try:
            metrics = _collect_fornex_for(base_url, server.fornex_vps_id, headers)
            stat = ServerStats(
                server_id=server.id,
                cpu_usage=metrics['cpu'],
                memory_usage=metrics['mem'],
                net_in_bytes=int(metrics['net_in']) if metrics['net_in'] is not None else None,
                net_out_bytes=int(metrics['net_out']) if metrics['net_out'] is not None else None,
            )
            db.session.add(stat)
            collected += 1
            logger.info(f"Fornex stats для {server.name} ({server.fornex_vps_id}): "
                        f"cpu={metrics['cpu']}% mem={metrics['mem']}%")
        except Exception as e:
            logger.error(f"Ошибка Fornex API для сервера {server.name}: {e}")

    # HAProxy серверы
    haproxy_servers = HaproxyServer.query.filter(HaproxyServer.fornex_vps_id.isnot(None)).all()
    for hap in haproxy_servers:
        try:
            metrics = _collect_fornex_for(base_url, hap.fornex_vps_id, headers)
            stat = HaproxyStats(
                haproxy_server_id=hap.id,
                cpu_usage=metrics['cpu'],
                memory_usage=metrics['mem'],
                net_in_bytes=int(metrics['net_in']) if metrics['net_in'] is not None else None,
                net_out_bytes=int(metrics['net_out']) if metrics['net_out'] is not None else None,
            )
            db.session.add(stat)
            collected += 1
            logger.info(f"Fornex stats для HAProxy {hap.name} ({hap.fornex_vps_id}): "
                        f"cpu={metrics['cpu']}% mem={metrics['mem']}%")
        except Exception as e:
            logger.error(f"Ошибка Fornex API для HAProxy {hap.name}: {e}")

    db.session.commit()
    return f"Собрана Fornex статистика для {collected} серверов"


@celery.task(bind=True)
def cleanup_session_tokens(self):
    """Удаляет неиспользуемые сессионные токены старше 7 дней"""
    cutoff = datetime.utcnow() - timedelta(days=7)
    old_tokens = ApiToken.query.filter(
        ApiToken.name.like('session_token_%'),
        ApiToken.last_used_at < cutoff
    ).all()

    for token in old_tokens:
        db.session.delete(token)

    db.session.commit()
    return f"Удалено {len(old_tokens)} старых токенов"


@celery.task(bind=True)
def install_protocol_task(self, protocol_id):
    """Асинхронная задача установки протокола с поддержкой Shared Keys для групп"""
    from app.protocols.utils import install_protocol_on_server
    protocol = ServerProtocol.query.get(protocol_id)
    if not protocol:
        return f"Protocol {protocol_id} not found"

    server = protocol.server
    logger.info(f"Starting installation of {protocol.protocol_type} on {server.name}")

    # Логика Shared Keys: если сервер в группе, ищем существующие ключи в этой группе
    custom_params = None
    if server.group_id:
        # Ищем любой сервер в этой же группе, где уже установлен этот протокол
        existing_protocol = ServerProtocol.query.join(Server).filter(
            Server.group_id == server.group_id,
            ServerProtocol.protocol_type == protocol.protocol_type,
            ServerProtocol.status == 'installed',
            ServerProtocol.id != protocol.id
        ).first()
        
        if existing_protocol and existing_protocol.config_params:
            logger.info(f"Found existing config for {protocol.protocol_type} in group {server.group.name}. Using shared keys.")
            custom_params = existing_protocol.config_params

    success, message, config_params = install_protocol_on_server(
        server, protocol.protocol_type, protocol.port, custom_params=custom_params
    )

    if success:
        protocol.status = 'installed'
        protocol.config_params = config_params
        logger.info(f"Successfully installed {protocol.protocol_type} on {server.name}")
    else:
        protocol.status = 'error'
        logger.error(f"Failed to install {protocol.protocol_type} on {server.name}: {message}")

    db.session.commit()
    return "Success" if success else f"Error: {message}"


@celery.task(bind=True)
def uninstall_protocol_task(self, protocol_id):
    """Асинхронная задача удаления протокола"""
    from app.protocols.utils import uninstall_protocol
    protocol = ServerProtocol.query.get(protocol_id)
    if not protocol:
        return f"Protocol {protocol_id} not found"

    server_name = protocol.server.name if protocol.server else "Unknown Server"
    proto_type = protocol.protocol_type
    
    logger.info(f"Removing protocol {proto_type} from server {server_name}")

    success, message = uninstall_protocol(protocol)

    if success:
        db.session.delete(protocol)
        db.session.commit()
        logger.info(f"Successfully removed protocol {protocol_id}")
    else:
        protocol.status = 'error'
        db.session.commit()
        logger.error(f"Failed to remove protocol {protocol_id}: {message}")

    return "Success" if success else f"Error: {message}"


@celery.task(bind=True)
def enable_group_reality_task(self, group_id, port, sni, haproxy_server_id):
    """Включает XRay Reality для группы: устанавливает контейнер на HAProxy (если нужно),
    генерирует relay UUID, добавляет его на abroad XRay серверы, деплоит конфиг."""
    import uuid as uuid_module
    from app.haproxy.manager import HaproxyManager
    from app.clients.utils import apply_relay_uuid_to_group_servers
    from app.utils.crypto import encrypt_data

    group = ServerGroup.query.get(group_id)
    haproxy_server = HaproxyServer.query.get(haproxy_server_id)
    if not group or not haproxy_server:
        return "Group or HAProxy server not found"

    manager = HaproxyManager(haproxy_server)

    # Установить XRay Reality если ещё не установлен
    if haproxy_server.xray_status != 'installed':
        haproxy_server.xray_status = 'installing'
        db.session.commit()

        success, public_key, private_key = manager.install_xray_reality_base()
        if not success:
            haproxy_server.xray_status = 'error'
            db.session.commit()
            logger.error(f"Failed to install XRay Reality on HAProxy {haproxy_server.name}")
            return "Failed to install XRay Reality"

        haproxy_server.xray_public_key = public_key
        haproxy_server.xray_private_key_encrypted = encrypt_data(private_key)
        haproxy_server.xray_status = 'installed'
        db.session.commit()

    # Сохранить Reality настройки для группы
    relay_uuid = str(uuid_module.uuid4())
    group.reality_relay_uuid = relay_uuid
    group.reality_enabled = True
    group.reality_port = port
    group.reality_sni = sni
    group.reality_haproxy_server_id = haproxy_server_id
    db.session.commit()

    # Добавить relay UUID на все XRay серверы группы
    try:
        apply_relay_uuid_to_group_servers(group, relay_uuid)
    except Exception as e:
        logger.error(f"Error applying relay UUID to group {group.name} servers: {e}")

    # Обновить конфиг XRay Reality на HAProxy
    try:
        success, message = manager.update_xray_reality_config()
        if not success:
            logger.error(f"Failed to update XRay Reality config for group {group.name}: {message}")
    except Exception as e:
        logger.error(f"Exception updating XRay Reality config: {e}")

    return f"Reality enabled for group {group.name}"


@celery.task(bind=True)
def disable_group_reality_task(self, group_id):
    """Отключает XRay Reality для группы и обновляет конфиг на HAProxy."""
    from app.haproxy.manager import HaproxyManager

    group = ServerGroup.query.get(group_id)
    if not group:
        return "Group not found"

    haproxy_server_id = group.reality_haproxy_server_id

    group.reality_enabled = False
    group.reality_port = None
    group.reality_relay_uuid = None
    group.reality_haproxy_server_id = None
    db.session.commit()

    if haproxy_server_id:
        haproxy_server = HaproxyServer.query.get(haproxy_server_id)
        if haproxy_server and haproxy_server.xray_status == 'installed':
            try:
                HaproxyManager(haproxy_server).update_xray_reality_config()
            except Exception as e:
                logger.error(f"Error updating XRay Reality config on disable: {e}")

    return f"Reality disabled for group {group.name if group else group_id}"


@celery.task(bind=True)
def apply_client_task(self, client_id):
    """Асинхронная задача применения клиента на сервере или группе серверов"""
    from app.clients.utils import apply_client_to_server
    client = Client.query.get(client_id)
    if not client:
        return f"Client {client_id} not found"

    # Если клиент привязан к группе
    if client.group_id:
        group_name = client.group.name if client.group else f"Group ID {client.group_id}"
        logger.info(f"Applying client {client.name} to server group {group_name}")
        
        if not client.group or not client.group.servers:
            logger.warning(f"No servers found in group {group_name}")
            return "No servers in group"

        servers = client.group.servers
        success_count = 0
        
        for server in servers:
            # Находим нужный протокол на этом конкретном сервере
            protocol = ServerProtocol.query.filter_by(
                server_id=server.id, 
                protocol_type=client.protocol_type,
                status='installed'
            ).first()
            
            if protocol:
                # Временно подменяем параметры для вызова функции
                # (Так как apply_client_to_server ожидает наличие связи client.server)
                orig_server = client.server
                orig_proto = client.protocol
                
                client.server = server
                client.protocol = protocol
                
                try:
                    success, message = apply_client_to_server(client)
                    if success:
                        success_count += 1
                    else:
                        logger.error(f"Failed to apply client {client.name} to server {server.name}: {message}")
                finally:
                    # Обязательно возвращаем как было
                    client.server = orig_server
                    client.protocol = orig_proto
        
        if success_count > 0:
            client.status = 'active'
            db.session.commit()

        # Если группа с Reality — обновить конфиг XRay Reality на HAProxy
        if client.group and client.group.reality_enabled and client.group.reality_haproxy_server_id:
            try:
                from app.haproxy.manager import HaproxyManager
                hs = HaproxyServer.query.get(client.group.reality_haproxy_server_id)
                if hs and hs.xray_status == 'installed':
                    HaproxyManager(hs).update_xray_reality_config()
            except Exception as e:
                logger.warning(f"Failed to update Reality config after applying client {client_id}: {e}")

        if success_count > 0:
            return f"Successfully applied to {success_count}/{len(servers)} servers"
        _mark_client_failed(client, f"Не удалось применить ни на одном сервере группы {group_name}")
        return "Failed to apply to any server in group"

    # Обычный клиент привязанный к одному серверу
    else:
        if not client.server:
            logger.error(f"Client {client.name} has no server assigned")
            _mark_client_failed(client, "Клиенту не назначен сервер")
            return "Error: No server assigned"

        logger.info(f"Applying client {client.name} to server {client.server.name}")
        success, message = apply_client_to_server(client)
        if success:
            client.status = 'active'
            _clear_client_error(client)
            db.session.commit()
            return "Success"
        _mark_client_failed(client, message)
        return f"Error: {message}"


def _mark_client_failed(client, message):
    """
    Переводит клиента в статус 'error' и сохраняет причину.

    Без этого неудачное применение оставляло клиента в 'pending' навсегда:
    задача Celery завершалась «успешно» с текстом ошибки в возвращаемом значении,
    которое нигде не читается, и в панели конфиг вечно висел как «применяется».
    Статус 'error' уже отрисовывается шаблонами и снимает блокировку с кнопки
    «Применить», так что повторить установку можно из UI.
    """
    try:
        client.status = 'error'
        extra = dict(client.extra_params or {})
        extra['last_error'] = str(message)[:500]
        client.extra_params = extra
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to mark client {client.id} as failed: {e}")
        db.session.rollback()


def _clear_client_error(client):
    """Убирает текст прошлой ошибки после успешного применения."""
    if client.extra_params and 'last_error' in client.extra_params:
        extra = dict(client.extra_params)
        extra.pop('last_error', None)
        client.extra_params = extra


@celery.task(bind=True)
def remove_client_task(self, client_id, delete_from_db=True):
    """Асинхронная задача удаления клиента с сервера"""
    from app.clients.utils import remove_client_from_server
    client = Client.query.get(client_id)
    if not client:
        return f"Client {client_id} not found"

    client_name = client.name

    # Групповой клиент — удаляем со всех серверов группы
    if client.group_id and not client.server_id:
        reality_haproxy_server_id = (
            client.group.reality_haproxy_server_id
            if client.group and client.group.reality_enabled else None
        )

        if client.group and client.group.servers:
            for server in client.group.servers:
                protocol = ServerProtocol.query.filter_by(
                    server_id=server.id,
                    protocol_type=client.protocol_type,
                    status='installed'
                ).first()
                if not protocol:
                    continue
                orig_server = client.server
                orig_proto = client.protocol
                client.server = server
                client.protocol = protocol
                try:
                    success, message = remove_client_from_server(client)
                    if not success:
                        logger.warning(f"Failed to remove client {client_name} from {server.name}: {message}")
                    else:
                        logger.info(f"Removed client {client_name} from {server.name}")
                finally:
                    client.server = orig_server
                    client.protocol = orig_proto

        if delete_from_db:
            db.session.delete(client)
            db.session.commit()

        # Обновить Reality конфиг (клиент больше не должен быть в inbound)
        if reality_haproxy_server_id:
            try:
                from app.haproxy.manager import HaproxyManager
                hs = HaproxyServer.query.get(reality_haproxy_server_id)
                if hs and hs.xray_status == 'installed':
                    HaproxyManager(hs).update_xray_reality_config()
            except Exception as e:
                logger.warning(f"Failed to update Reality config after removing client {client_id}: {e}")

        return "Success"

    if not client.server:
        if delete_from_db:
            db.session.delete(client)
            db.session.commit()
        return "Success"

    server_name = client.server.name
    logger.info(f"Removing client {client_name} from server {server_name}")

    success, message = remove_client_from_server(client)

    if success:
        if delete_from_db:
            db.session.delete(client)
            db.session.commit()
        logger.info(f"Successfully removed client {client_id} from server")
    else:
        logger.error(f"Failed to remove client {client_id} from server: {message}")

    return "Success" if success else f"Error: {message}"


@celery.task(bind=True)
def restart_protocol_task(self, protocol_id):
    """Асинхронная задача перезапуска протокола"""
    protocol = ServerProtocol.query.get(protocol_id)
    if not protocol:
        return f"Protocol {protocol_id} not found"

    server = protocol.server

    key = decrypt_data(server.ssh_key_encrypted)
    passphrase = decrypt_data(server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None

    if protocol.protocol_type == 'awg':
        command = "sudo systemctl restart awg-quick@wg0"
    elif protocol.protocol_type == 'xray':
        command = "sudo docker restart xray-reality"
    elif protocol.protocol_type == 'openvpn':
        command = "sudo docker restart openvpn"
    else:
        return f"Unknown protocol: {protocol.protocol_type}"
    exit_code, stdout, stderr = execute_ssh_command(
        server.ip, server.ssh_port, server.ssh_username,
        key, command, passphrase
    )

    if exit_code == 0:
        logger.info(f"Protocol {protocol.protocol_type} on {server.name} restarted")
        return "Success"
    else:
        logger.error(f"Failed to restart protocol {protocol.protocol_type}: {stderr}")
        return f"Error: {stderr}"


@celery.task(bind=True)
def cleanup_deleted_oidc_users(self):
    """
    Ночная задача: проверяет каждого OIDC-пользователя через провайдер
    и удаляет тех, кого больше нет или кто заблокирован.

    Алгоритм для каждого юзера:
    1. Берём сохранённый refresh_token и обновляем его через /oauth/token
    2. Вызываем /oauth/userinfo с новым access_token
    3. invalid_grant при refresh  → удаляем (токен отозван / юзер удалён из провайдера)
       invalid_token при userinfo → удаляем (юзер удалён из Users в провайдере)
       block: true в userinfo     → блокируем клиентов юзера
    4. Сохраняем новый refresh_token для следующего запуска
    """
    import requests
    from app.models import OIDCSetting, OIDCUser
    from app.utils.crypto import encrypt_data

    setting = OIDCSetting.get()
    if not setting:
        return "OIDC не настроен, пропускаем"

    client_secret = decrypt_data(setting.client_secret_encrypted)

    # Определяем token_endpoint и userinfo_endpoint
    token_url = setting.token_url
    userinfo_url = setting.userinfo_url
    if not token_url or not userinfo_url:
        try:
            disc = requests.get(
                f"{setting.provider_url.rstrip('/')}/.well-known/openid-configuration",
                timeout=10
            )
            disc.raise_for_status()
            data = disc.json()
            token_url = token_url or data.get('token_endpoint')
            userinfo_url = userinfo_url or data.get('userinfo_endpoint')
        except Exception as e:
            logger.error(f"cleanup_oidc_users: discovery failed: {e}")
            return f"Не удалось получить endpoints: {e}"

    if not token_url or not userinfo_url:
        return "token_endpoint или userinfo_endpoint не найдены"

    users = OIDCUser.query.all()
    deleted, blocked, skipped = 0, 0, 0

    for user in users:
        if not user.refresh_token_encrypted:
            # refresh_token не сохранён — юзер заходил до внедрения этой фичи,
            # пропускаем (удалим при следующем его логине или вручную)
            skipped += 1
            continue

        try:
            refresh_token = decrypt_data(user.refresh_token_encrypted)
        except Exception as e:
            logger.error(f"cleanup_oidc_users: не удалось расшифровать токен юзера {user.id}: {e}")
            skipped += 1
            continue

        # --- Шаг 1: обновляем токен ---
        try:
            r = requests.post(token_url, data={
                'grant_type': 'refresh_token',
                'client_id': setting.client_id,
                'client_secret': client_secret,
                'refresh_token': refresh_token,
            }, timeout=10)
        except Exception as e:
            logger.error(f"cleanup_oidc_users: ошибка запроса токена для {user.sub}: {e}")
            skipped += 1
            continue

        if r.status_code != 200 or r.json().get('error') == 'invalid_grant':
            # Refresh token недействителен — удаляем юзера
            Client.query.filter_by(oidc_user_id=user.id).update({'oidc_user_id': None})
            db.session.delete(user)
            db.session.commit()
            deleted += 1
            logger.info(f"cleanup_oidc_users: удалён {user.email or user.sub} (invalid_grant)")
            continue

        token_data = r.json()
        access_token = token_data.get('access_token')
        new_refresh_token = token_data.get('refresh_token')

        if not access_token:
            skipped += 1
            continue

        # --- Шаг 2: проверяем userinfo ---
        try:
            ui = requests.get(userinfo_url, headers={
                'Authorization': f'Bearer {access_token}'
            }, timeout=10)
        except Exception as e:
            logger.error(f"cleanup_oidc_users: ошибка userinfo для {user.sub}: {e}")
            skipped += 1
            continue

        if ui.status_code == 401:
            # Юзер удалён из базы провайдера
            Client.query.filter_by(oidc_user_id=user.id).update({'oidc_user_id': None})
            db.session.delete(user)
            db.session.commit()
            deleted += 1
            logger.info(f"cleanup_oidc_users: удалён {user.email or user.sub} (invalid_token от userinfo)")
            continue

        if ui.status_code == 200:
            info = ui.json()

            if info.get('block'):
                # Юзер заблокирован на провайдере — блокируем его клиентов
                Client.query.filter_by(oidc_user_id=user.id).update({'status': 'blocked'})
                db.session.commit()
                blocked += 1
                logger.info(f"cleanup_oidc_users: заблокированы клиенты {user.email or user.sub} (block=true)")
            else:
                # Всё в порядке — обновляем имя/email и сохраняем новый refresh_token
                user.email = info.get('email', user.email)
                user.name = info.get('name', user.name)

            if new_refresh_token:
                user.refresh_token_encrypted = encrypt_data(new_refresh_token)
            db.session.commit()

        else:
            logger.warning(f"cleanup_oidc_users: userinfo вернул {ui.status_code} для {user.sub}")
            skipped += 1

    return f"Готово: удалено={deleted}, заблокировано={blocked}, пропущено={skipped}, всего={len(users)}"