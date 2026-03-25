import base64
import json
import time
import uuid
import re
import zlib

from app import db
from app.utils.crypto import encrypt_data, decrypt_data
from app.servers.ssh import execute_ssh_command


def generate_wg_keys():
    """Генерирует пару ключей WireGuard (X25519) через библиотеку cryptography."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    import base64

    priv = X25519PrivateKey.generate()
    private_b64 = base64.b64encode(
        priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()
    public_b64 = base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return private_b64, public_b64


def generate_xray_keys():
    """Генерирует UUID для XRay"""
    return str(uuid.uuid4())


def get_next_client_ip(server_id=None, protocol_id=None, group_id=None, protocol_type=None):
    """
    Определяет следующий свободный IP адрес для клиента в подсети 10.8.0.0/24.

    Для одиночного клиента: ищет по server_id + protocol_id.
    Для группового клиента: ищет по group_id + protocol_type.
    В обоих случаях также проверяет конкурирующий тип, чтобы избежать коллизий.
    """
    from app.models import Client

    used_ips = set()

    def _extract_octets(clients):
        for c in clients:
            if c.extra_params and 'assigned_ip' in c.extra_params:
                m = re.search(r'10\.8\.0\.(\d+)', c.extra_params['assigned_ip'])
                if m:
                    used_ips.add(int(m.group(1)))

    if group_id:
        # Все клиенты группы с этим протоколом (group_id=group_id, server_id=NULL)
        _extract_octets(Client.query.filter_by(
            group_id=group_id,
            protocol_type=protocol_type
        ).all())
    elif server_id and protocol_id:
        # Прямые клиенты сервера
        _extract_octets(Client.query.filter_by(
            server_id=server_id,
            protocol_id=protocol_id
        ).all())

    # Ищем первый свободный IP от 2 до 254 (10.8.0.1 занят сервером)
    for i in range(2, 255):
        if i not in used_ips:
            return f"10.8.0.{i}"

    raise ValueError("Нет свободных IP адресов в подсети 10.8.0.0/24")


def apply_client_to_server(client):
    """
    Добавляет клиента на сервер через SSH
    Возвращает (success, message)
    """
    server = client.server
    protocol = client.protocol

    # Расшифровываем SSH-ключ
    ssh_key = decrypt_data(server.ssh_key_encrypted)
    passphrase = decrypt_data(server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None

    if protocol.protocol_type == 'awg':
        assigned_ip = client.extra_params['assigned_ip']

        public_key = client.public_key
        psk_encrypted = client.extra_params.get('psk')
        psk = decrypt_data(psk_encrypted) if psk_encrypted else None

        commands = []

        # Формируем команду для добавления пира в WireGuard
        if psk:
            psk = psk.strip()
            temp_file = f"/tmp/psk_{client.id}_{int(time.time())}"
            commands = [
                f"printf '%s' '{psk}' | sudo tee {temp_file} > /dev/null",
                f"sudo awg set wg0 peer {public_key} preshared-key {temp_file} allowed-ips {assigned_ip}/32",
                f"sudo rm {temp_file}"
            ]
        else:
            commands.append(f"sudo awg set wg0 peer {public_key} allowed-ips {assigned_ip}/32")

        # Сохраняем конфигурацию
        commands.append("sudo awg-quick save /opt/amnezia/awg/conf/wg0.conf")

        # Объединяем команды
        full_command = " && ".join(commands)

        # Выполняем команды
        exit_code, stdout, stderr = execute_ssh_command(
            server.ip, server.ssh_port, server.ssh_username,
            ssh_key, full_command, passphrase
        )

        if exit_code == 0:
            return True, f"Клиент добавлен в WireGuard с IP {assigned_ip}"
        else:
            return False, stderr or stdout

    elif protocol.protocol_type == 'xray':
        # Команда для получения конфига
        get_cmd = "cat /opt/amnezia/xray/config.json"
        exit_code, stdout, stderr = execute_ssh_command(
            server.ip, server.ssh_port, server.ssh_username,
            ssh_key, get_cmd, passphrase
        )
        if exit_code != 0:
            return False, "Не удалось прочитать конфиг XRay"

        try:
            config = json.loads(stdout)
        except:
            return False, "Ошибка парсинга JSON"

        # Добавляем клиента в конфиг
        for inbound in config.get('inbounds', []):
            if inbound.get('protocol') == 'vless' and inbound.get('streamSettings', {}).get(
                    'security') == 'reality':
                clients = inbound['settings'].setdefault('clients', [])
                new_client = {
                    'id': client.extra_params.get('uuid'),
                    'email': client.email or f"{client.name}@example.com",
                    'flow': 'xtls-rprx-vision'
                }
                clients.append(new_client)
                break

        # Сохраняем конфиг
        new_config_json = json.dumps(config, indent=2)
        escaped_json = new_config_json.replace("'", "'\\''")
        write_cmd = f"echo '{escaped_json}' | sudo tee /opt/amnezia/xray/config.json > /dev/null"

        execute_ssh_command(server.ip, server.ssh_port, server.ssh_username,
                            ssh_key, write_cmd, passphrase)

        # Отправляем сигнал HUP для перезагрузки конфигурации без остановки соединений
        hup_cmd = "sudo docker exec xray-reality kill -HUP 1"

        exit_code, stdout, stderr = execute_ssh_command(
            server.ip, server.ssh_port, server.ssh_username,
            ssh_key, hup_cmd, passphrase
        )

        if exit_code == 0:
            return True, "Клиент добавлен (конфиг перезагружен через HUP)"
        else:
            return False, f"Ошибка отправки HUP: {stderr or stdout}"

    else:
        return False, f"Неподдерживаемый протокол: {protocol.protocol_type}"


def remove_client_from_server(client):
    """
    Удаляет клиента с сервера через SSH
    Возвращает (success, message)
    """
    server = client.server
    protocol = client.protocol

    # Расшифровываем SSH-ключ
    ssh_key = decrypt_data(server.ssh_key_encrypted)
    passphrase = decrypt_data(server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None

    if protocol.protocol_type == 'awg':
        public_key = client.public_key
        command = f"sudo awg set wg0 peer {public_key} remove"

        exit_code, stdout, stderr = execute_ssh_command(
            server.ip, server.ssh_port, server.ssh_username,
            ssh_key, command, passphrase
        )

        if exit_code == 0:
            save_cmd = "sudo awg-quick save /opt/amnezia/awg/conf/wg0.conf"
            execute_ssh_command(server.ip, server.ssh_port, server.ssh_username, ssh_key, save_cmd, passphrase)

            if 'assigned_ip' in client.extra_params:
                del client.extra_params['assigned_ip']
                db.session.commit()

            return True, "Клиент удален из WireGuard"
        else:
            return False, stderr or stdout

    elif protocol.protocol_type == 'xray':
        get_cmd = "cat /opt/amnezia/xray/config.json"
        exit_code, stdout, stderr = execute_ssh_command(
            server.ip, server.ssh_port, server.ssh_username,
            ssh_key, get_cmd, passphrase
        )

        if exit_code != 0:
            return False, "Не удалось прочитать конфиг XRay"

        try:
            config = json.loads(stdout)
        except json.JSONDecodeError as e:
            return False, f"Ошибка парсинга JSON: {str(e)}"

        client_removed = False
        client_uuid = client.extra_params.get('uuid')
        client_email = client.email or f"{client.name}@example.com"

        for inbound in config.get('inbounds', []):
            if inbound.get('protocol') == 'vless' and inbound.get('streamSettings', {}).get('security') == 'reality':
                clients = inbound['settings'].get('clients', [])
                original_count = len(clients)
                inbound['settings']['clients'] = [
                    c for c in clients
                    if c.get('id') != client_uuid and c.get('email') != client_email
                ]

                if len(inbound['settings']['clients']) < original_count:
                    client_removed = True
                break

        if not client_removed:
            return False, "Клиент не найден в конфиге"

        new_config_json = json.dumps(config, indent=2)
        escaped_json = new_config_json.replace("'", "'\\''")
        write_cmd = f"echo '{escaped_json}' | sudo tee /opt/amnezia/xray/config.json > /dev/null"

        exit_code, stdout, stderr = execute_ssh_command(
            server.ip, server.ssh_port, server.ssh_username,
            ssh_key, write_cmd, passphrase
        )

        if exit_code != 0:
            return False, f"Не удалось записать конфиг: {stderr or stdout}"

        restart_cmd = "sudo docker exec xray-reality kill -HUP 1"
        exit_code, stdout, stderr = execute_ssh_command(
            server.ip, server.ssh_port, server.ssh_username,
            ssh_key, restart_cmd, passphrase
        )

        if exit_code == 0:
            return True, "Клиент удален из XRay"
        else:
            return False, f"Ошибка перезапуска XRay: {stderr or stdout}"

    return False, f"Неподдерживаемый протокол: {protocol.protocol_type}"


def apply_relay_uuid_to_group_servers(group, relay_uuid):
    """Добавляет relay UUID на все XRay серверы группы (нужен для Reality chaining)."""
    from app.models import ServerProtocol

    relay_entry = {
        'id': relay_uuid,
        'email': 'relay@reality',
        'flow': 'xtls-rprx-vision'
    }

    for server in group.servers:
        protocol = ServerProtocol.query.filter_by(
            server_id=server.id,
            protocol_type='xray',
            status='installed'
        ).first()
        if not protocol:
            continue

        ssh_key = decrypt_data(server.ssh_key_encrypted)
        passphrase = decrypt_data(server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None

        get_cmd = "cat /opt/amnezia/xray/config.json"
        exit_code, stdout, stderr = execute_ssh_command(
            server.ip, server.ssh_port, server.ssh_username,
            ssh_key, get_cmd, passphrase
        )
        if exit_code != 0:
            continue

        try:
            config = json.loads(stdout)
        except json.JSONDecodeError:
            continue

        for inbound in config.get('inbounds', []):
            if inbound.get('protocol') == 'vless':
                clients = inbound['settings'].setdefault('clients', [])
                if not any(c.get('id') == relay_uuid for c in clients):
                    clients.append(relay_entry)
                break
        else:
            continue  # no vless inbound found

        new_config_json = json.dumps(config, indent=2)
        escaped_json = new_config_json.replace("'", "'\\''")
        write_cmd = f"echo '{escaped_json}' | sudo tee /opt/amnezia/xray/config.json > /dev/null"
        exit_code, _, _ = execute_ssh_command(
            server.ip, server.ssh_port, server.ssh_username,
            ssh_key, write_cmd, passphrase
        )
        if exit_code != 0:
            continue

        execute_ssh_command(
            server.ip, server.ssh_port, server.ssh_username,
            ssh_key, "sudo docker exec xray-reality kill -HUP 1", passphrase
        )


def resolve_client_endpoint(client):
    """Возвращает (address, port) для клиента с учётом HAProxy и групповых клиентов."""
    connection_address = client.server.ip if client.server else None
    connection_port = client.protocol.port if client.protocol else None

    if client.group_id:
        group = client.group
        # Reality group: вернуть Reality endpoint на HAProxy
        if (group and group.reality_enabled and group.reality_haproxy_server_id
                and group.reality_port and client.protocol_type == 'xray'):
            hs = group.reality_haproxy_server
            if hs and hs.xray_status == 'installed':
                return hs.ip, group.reality_port

        from app.models import HaproxyBackend
        proto_type = client.protocol_type
        backend = HaproxyBackend.query.filter_by(
            protocol_type=proto_type,
            group_id=client.group_id
        ).first()
        if not backend:
            backend = HaproxyBackend.query.filter_by(
                protocol_type=proto_type,
                group_id=None
            ).first()
        if backend and backend.haproxy_server:
            connection_address = backend.haproxy_server.ip
            connection_port = backend.port
        elif client.group and client.group.servers:
            for srv in client.group.servers:
                proto = next(
                    (p for p in srv.protocols
                     if p.protocol_type == proto_type and p.status == 'installed'),
                    None
                )
                if proto:
                    connection_address = srv.ip
                    connection_port = proto.port
                    break

    return connection_address, connection_port


def generate_client_config(client):
    """Генерирует конфигурационный файл для клиента"""
    from flask import current_app

    connection_address, connection_port = resolve_client_endpoint(client)

    current_app.logger.info(
        f"generate_client_config: client={client.id} proto={client.protocol_type} "
        f"addr={connection_address} port={connection_port}"
    )

    if not connection_address:
        current_app.logger.warning(f"generate_client_config: no endpoint found for client {client.id}")
        return None

    proto_type = client.protocol_type or (client.protocol.protocol_type if client.protocol else None)

    if proto_type == 'awg':
        return generate_amnezia_vpn_uri(client, connection_address, connection_port)

    elif proto_type == 'xray':
        uuid = client.extra_params.get('uuid')
        public_key = None
        sni = 'www.microsoft.com'

        # Reality через HAProxy: используем ключ и SNI с HAProxy сервера
        if client.group_id and client.group and client.group.reality_enabled:
            hs = client.group.reality_haproxy_server
            if hs:
                public_key = hs.xray_public_key
                sni = client.group.reality_sni or 'www.microsoft.com'

        # Обычный XRay: ключ из ServerProtocol или первого сервера группы
        if public_key is None:
            if client.protocol:
                public_key = client.protocol.config_params.get('public_key')
            elif client.group:
                for srv in client.group.servers:
                    proto = next(
                        (p for p in srv.protocols if p.protocol_type == 'xray' and p.status == 'installed'),
                        None
                    )
                    if proto:
                        public_key = proto.config_params.get('public_key')
                        break

        params = {
            'security': 'reality',
            'encryption': 'none',
            'pbk': public_key,
            'sid': '6ba85179e30d4fc2',
            'type': 'tcp',
            'flow': 'xtls-rprx-vision',
            'sni': sni
        }
        query = '&'.join([f"{k}={v}" for k, v in params.items() if v])
        return f"vless://{uuid}@{connection_address}:{connection_port}?{query}#{client.name}"

    return None

def _get_awg_params(client):
    """Возвращает (params, assigned_ip, private_key, psk) для AWG клиента."""
    params = {}
    if client.protocol:
        params = client.protocol.config_params
    elif client.group:
        for srv in client.group.servers:
            proto = next((p for p in srv.protocols if p.protocol_type == 'awg' and p.status == 'installed'), None)
            if proto:
                params = proto.config_params
                break

    assigned_ip = client.extra_params.get('assigned_ip')
    private_key = decrypt_data(client.private_key_encrypted) if client.private_key_encrypted else ""
    psk = decrypt_data(client.extra_params.get('psk')) if client.extra_params.get('psk') else None
    return params, assigned_ip, private_key, psk


def generate_amnezia_vpn_uri(client, address, port):
    """Генерирует конфиг для AmneziaWG в формате INI."""
    params, assigned_ip, private_key, psk = _get_awg_params(client)
    return generate_awg_config(client, params, assigned_ip, private_key, psk, address, port)


def generate_amnezia_export_json(client, address, port):
    """Генерирует JSON-экспорт для AmneziaVPN (для QR-кода / импорта).

    Формат соответствует нативному экспорту Amnezia-сервера:
    - awg-объект содержит все AWG-параметры как строки + last_config (JSON-строка)
    - last_config содержит полные данные подключения + поле config (WireGuard INI)
    - В INI внутри last_config DNS задаётся через плейсхолдеры $PRIMARY_DNS/$SECONDARY_DNS
    """
    import json
    params, assigned_ip, private_key, psk = _get_awg_params(client)

    jc   = str(params.get('jc',   5))
    jmin = str(params.get('jmin', 10))
    jmax = str(params.get('jmax', 50))
    s1   = str(params.get('s1',   76))
    s2   = str(params.get('s2',   17))
    h1   = str(params.get('h1',   972258040))
    h2   = str(params.get('h2',   1405819692))
    h3   = str(params.get('h3',   1069365787))
    h4   = str(params.get('h4',   1451939155))
    mtu  = str(params.get('mtu',  1376))
    server_pub_key = params.get('server_public_key', '')
    client_pub_key = client.public_key or ''

    # WireGuard INI внутри last_config — DNS через плейсхолдеры, адрес /32
    ini_lines = [
        "[Interface]",
        f"Address = {assigned_ip}/32",
        "DNS = $PRIMARY_DNS, $SECONDARY_DNS",
        f"PrivateKey = {private_key}",
        f"Jc = {jc}",
        f"Jmin = {jmin}",
        f"Jmax = {jmax}",
        f"S1 = {s1}",
        f"S2 = {s2}",
        f"H1 = {h1}",
        f"H2 = {h2}",
        f"H3 = {h3}",
        f"H4 = {h4}",
        "",
        "[Peer]",
        f"PublicKey = {server_pub_key}",
    ]
    if psk:
        ini_lines.append(f"PresharedKey = {psk}")
    ini_lines += [
        "AllowedIPs = 0.0.0.0/0, ::/0",
        f"Endpoint = {address}:{port}",
        "PersistentKeepalive = 25",
        "",
    ]
    ini_config = "\n".join(ini_lines)

    # JSON-объект last_config (будет сериализован в строку)
    last_config_obj = {
        "H1": h1, "H2": h2, "H3": h3, "H4": h4,
        "Jc": jc, "Jmax": jmax, "Jmin": jmin,
        "S1": s1, "S2": s2,
        "allowed_ips": ["0.0.0.0/0", "::/0"],
        "clientId": client_pub_key,
        "client_ip": assigned_ip,
        "client_priv_key": private_key,
        "client_pub_key": client_pub_key,
        "config": ini_config,
        "hostName": str(address),
        "mtu": mtu,
        "persistent_keep_alive": "25",
        "port": int(port),
        "psk_key": psk or "",
        "server_pub_key": server_pub_key,
    }

    awg_obj = {
        "H1": h1, "H2": h2, "H3": h3, "H4": h4,
        "Jc": jc, "Jmax": jmax, "Jmin": jmin,
        "S1": s1, "S2": s2,
        "last_config": json.dumps(last_config_obj, indent=4, ensure_ascii=False) + "\n",
        "port": str(port),
        "transport_proto": "udp",
    }

    export = {
        "containers": [{"container": "amnezia-awg", "awg": awg_obj}],
        "defaultContainer": "amnezia-awg",
        "description": client.name or "AmneziaVPN",
        "dns1": "1.1.1.1",
        "dns2": "1.0.0.1",
        "hostName": str(address),
        "nameOverriddenByUser": True,
    }
    return encode_config(export)

def encode_config(config):
    """Encodes a JSON configuration into a vpn:// prefixed string."""
    # Use indent=4 to preserve indentation,
    json_str = json.dumps(config, indent=4).encode()

    # Compress data using zlib
    compressed_data = zlib.compress(json_str)

    # Add a 4-byte header with the original data length in big-endian format
    original_data_len = len(json_str)
    header = original_data_len.to_bytes(4, byteorder='big')

    # Combine header and compressed data, then encode with Base64
    encoded_data = base64.urlsafe_b64encode(header + compressed_data).decode().rstrip("=")
    return f"{encoded_data}"

def generate_awg_config(client, params, assigned_ip, private_key, psk="", address=None, port=None):
    """Генерирует конфиг AmneziaWG 2.0 в формате INI"""
    if not address: address = client.server.ip if client.server else ""
    if not port: port = client.protocol.port if client.protocol else ""

    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {assigned_ip}/24",
        "DNS = 8.8.8.8",
        f"Jc = {params.get('jc', 5)}",
        f"Jmin = {params.get('jmin', 30)}",
        f"Jmax = {params.get('jmax', 50)}",
        f"S1 = {params.get('s1', 220)}",
        f"S2 = {params.get('s2', 230)}",
        f"H1 = {params.get('h1', 1855549004)}",
        f"H2 = {params.get('h2', 2882373428)}",
        f"H3 = {params.get('h3', 3625691520)}",
        f"H4 = {params.get('h4', 3868285620)}",
        f"MTU = {params.get('mtu', 1420)}",
        "",
        "[Peer]",
        f"PublicKey = {params.get('server_public_key')}",
        f"Endpoint = {address}:{port}",
        "AllowedIPs = 0.0.0.0/0",
        "PersistentKeepalive = 25"
    ]
    if psk:
        lines.insert(-4, f"PresharedKey = {psk}")

    return "\n".join(lines)

def generate_wg_psk():
    import secrets
    import base64
    return base64.b64encode(secrets.token_bytes(32)).decode()


def generate_keys_for_client(client):
    """Generate keys for a client (AWG or XRay). Used by portal and admin routes."""
    protocol_type = client.protocol_type
    if not protocol_type and client.protocol:
        protocol_type = client.protocol.protocol_type

    if protocol_type == 'awg':
        private_key, public_key = generate_wg_keys()
        psk = generate_wg_psk()
        client.public_key = public_key
        client.private_key_encrypted = encrypt_data(private_key)
        extra_params = dict(client.extra_params or {})
        extra_params['psk'] = encrypt_data(psk)

        if 'assigned_ip' not in extra_params:
            if client.group_id:
                # Групповой клиент: ищем свободный IP среди всех клиентов группы
                assigned_ip = get_next_client_ip(
                    group_id=client.group_id,
                    protocol_type='awg'
                )
                extra_params['assigned_ip'] = assigned_ip
            elif client.server_id and client.protocol_id:
                assigned_ip = get_next_client_ip(
                    server_id=client.server_id,
                    protocol_id=client.protocol_id
                )
                extra_params['assigned_ip'] = assigned_ip

        client.extra_params = extra_params
        db.session.commit()

    elif protocol_type == 'xray':
        uuid_val = generate_xray_keys()
        extra_params = dict(client.extra_params or {})
        extra_params['uuid'] = uuid_val
        extra_params['email'] = client.email or f"{client.name}@client"
        client.extra_params = extra_params
        db.session.commit()
