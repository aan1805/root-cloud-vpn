from app.extensions import db
from app.servers.ssh import execute_ssh_command
from app.utils.crypto import decrypt_data
from app.protocols.docker_installer import (
    install_docker_if_needed,
    install_amnezia_wg,
    install_xray_reality,
    install_openvpn_cloak
)
import json
import re

def install_protocol_on_server(server, protocol_type, port, custom_params=None):
    """
    Установка протокола через Docker
    """
    # Расшифровываем ключи
    key = decrypt_data(server.ssh_key_encrypted)
    passphrase = decrypt_data(server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None

    # 1. Установка Docker, если нужно
    script_parts = [
        "#!/bin/bash",
        "set -e",  # остановка при ошибке
        "",
        install_docker_if_needed(server),
        ""
    ]

    # 2. Команды для конкретного протокола
    if protocol_type == 'awg':
        script_parts.append(install_amnezia_wg(port, custom_params))
    elif protocol_type == 'xray':
        script_parts.append(install_xray_reality(port, custom_params))
    elif protocol_type == 'openvpn':
        script_parts.append(install_openvpn_cloak(port))
    else:
        return False, "Неподдерживаемый протокол", {}

    # Объединяем команды
    full_command = "\n\n".join(script_parts)

    # Выполняем через SSH
    exit_code, stdout, stderr = execute_ssh_command(
        server.ip, server.ssh_port, server.ssh_username,
        key, full_command, passphrase
    )

    if exit_code == 0:
        # Парсим результат для получения ключей
        config_params = {}

        if protocol_type == 'awg':
            # Ищем JSON между маркерами
            pattern = r'\{[^{}]*\}'
            matches = re.findall(pattern, stdout, re.DOTALL)

            if matches:
                # Берём последний JSON (params.json)
                last_json = matches[-1]
                try:
                    config_params = json.loads(last_json)
                except json.JSONDecodeError as e:
                    print(f"JSON decode error: {e}")
                    config_params = {}
            else:
                config_params = {}

        elif protocol_type == 'xray':
            # Парсим оба ключа из JSON-маркера (нужны для Shared Keys в группах)
            match = re.search(r'XRAY_KEYS_JSON:(\{"private_key"[^}]+\})', stdout)
            if match:
                try:
                    keys = json.loads(match.group(1))
                    config_params['private_key'] = keys.get('private_key', '')
                    config_params['public_key'] = keys.get('public_key', '')
                except json.JSONDecodeError:
                    config_params['public_key'] = stdout.strip()
            else:
                config_params['public_key'] = stdout.strip()
            config_params['short_id'] = '6ba85179e30d4fc2'  # из шаблона
            config_params['server_name'] = 'www.microsoft.com'

        return True, stdout, config_params
    else:
        return False, stderr or stdout, {}


def uninstall_protocol(protocol):
    """
    Удаление протокола (остановка и удаление контейнера)
    """
    server = protocol.server

    key = decrypt_data(server.ssh_key_encrypted)
    passphrase = decrypt_data(server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None

    dir_path = {
        'awg': '/opt/amnezia/awg',
        'xray': '/opt/amnezia/xray',
        'openvpn': '/opt/amnezia/openvpn'
    }.get(protocol.protocol_type)

    if not dir_path:
        return False, "Неизвестный протокол"

    command = f"cd {dir_path} && sudo docker-compose down -v && cd .. && sudo rm -rf {dir_path}"

    exit_code, stdout, stderr = execute_ssh_command(
        server.ip, server.ssh_port, server.ssh_username,
        key, command, passphrase
    )

    return exit_code == 0, stderr or stdout
