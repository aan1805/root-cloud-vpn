from app.celery_app import celery
from app.models import Client, Server, ServerProtocol, ServerStats, TrafficStats, ApiToken
from app.extensions import db
from app.servers.ssh import execute_ssh_command
from app.utils.crypto import decrypt_data
from datetime import datetime, date, timedelta
import logging

logger = logging.getLogger(__name__)


@celery.task(bind=True)
def collect_all_stats(self):
    """Собирает статистику со всех серверов"""
    servers = Server.query.filter_by(status='online').all()
    for server in servers:
        collect_server_stats.delay(server.id)
        collect_detailed_wg_stats.delay(server.id)
        collect_server_resources.delay(server.id)
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
        client = Client.query.filter_by(
            server_id=server.id,
            protocol_id=protocol.id,
            public_key=public_key
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
            # Ищем клиента по email или по extra_params['email']
            client = Client.query.filter(
                Client.server_id == server.id,
                Client.protocol_id == protocol.id,
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

                if client:
                    # Сохраняем статистику за сегодня
                    today = date.today()
                    stats = TrafficStats.query.filter_by(
                        client_id=client.id,
                        date=today
                    ).first()

                    if not stats:
                        stats = TrafficStats(
                            client_id=client.id,
                            date=today,
                            bytes_received=rx_bytes,
                            bytes_sent=tx_bytes
                        )
                        db.session.add(stats)
                    else:
                        stats.bytes_received = rx_bytes
                        stats.bytes_sent = tx_bytes

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
            return f"Successfully applied to {success_count}/{len(servers)} servers"
        return "Failed to apply to any server in group"

    # Обычный клиент привязанный к одному серверу
    else:
        if not client.server:
            logger.error(f"Client {client.name} has no server assigned")
            return "Error: No server assigned"
            
        logger.info(f"Applying client {client.name} to server {client.server.name}")
        success, message = apply_client_to_server(client)
        if success:
            client.status = 'active'
            db.session.commit()
            return "Success"
        return f"Error: {message}"


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