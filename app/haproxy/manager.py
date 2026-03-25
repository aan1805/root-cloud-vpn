import paramiko
import time
import json
import re
from io import StringIO
from app.utils.crypto import decrypt_data
from app.servers.ssh import parse_private_key

NGINX_STREAM_CONF = '/etc/nginx/stream.d/rootcloud.conf'


class HaproxyManager:
    def __init__(self, server):
        """
        server: объект HaproxyServer
        """
        self.server = server
        self.ssh_key = decrypt_data(server.ssh_key_encrypted)
        self.passphrase = decrypt_data(
            server.ssh_key_passphrase_encrypted) if server.ssh_key_passphrase_encrypted else None
        self.host = server.ip
        self.ssh_port = server.port
        self.username = server.ssh_username
        self.config_path = server.config_path
        self.socket_path = server.stats_socket_path

    def _execute_ssh(self, command):
        """Выполняет SSH команду на сервере"""
        try:
            pkey = parse_private_key(self.ssh_key, self.passphrase)

            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, port=self.ssh_port, username=self.username, pkey=pkey, timeout=30)

            stdin, stdout, stderr = client.exec_command(command)
            exit_code = stdout.channel.recv_exit_status()
            output = stdout.read().decode('utf-8')
            error = stderr.read().decode('utf-8')
            client.close()
            return exit_code, output, error

        except Exception as e:
            return -1, "", str(e)

    def _sftp_write(self, content, remote_path):
        """Записывает content в remote_path через SFTP (безопасно для любого содержимого)"""
        try:
            pkey = parse_private_key(self.ssh_key, self.passphrase)

            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(self.host, port=self.ssh_port, username=self.username, pkey=pkey, timeout=30)

            sftp = ssh_client.open_sftp()
            with sftp.file(remote_path, 'w') as f:
                f.write(content)
            sftp.close()
            ssh_client.close()
            return True, ""
        except Exception as e:
            return False, str(e)

    def _execute_socket_command(self, command):
        """Отправляет команду в HAProxy stats socket"""
        cmd = f"echo '{command}' | socat stdio {self.socket_path}"
        return self._execute_ssh(cmd)

    def get_config(self):
        """Получает текущую конфигурацию HAProxy"""
        return self._execute_ssh(f"cat {self.config_path}")

    def save_config(self, config_content):
        """Сохраняет конфигурацию HAProxy на сервер с валидацией и бэкапом"""
        temp_file = f"/tmp/haproxy.cfg.{int(time.time())}"

        ok, err = self._sftp_write(config_content, temp_file)
        if not ok:
            return False, f"Ошибка записи временного файла: {err}"

        # Валидируем перед применением
        exit_code, out, err = self._execute_ssh(f"haproxy -c -f {temp_file}")
        if exit_code != 0:
            self._execute_ssh(f"rm {temp_file}")
            return False, f"Ошибка валидации конфигурации: {err or out}"

        self._execute_ssh(f"sudo cp {self.config_path} {self.config_path}.bak")

        exit_code, out, err = self._execute_ssh(
            f"sudo cp {temp_file} {self.config_path} && sudo rm {temp_file}"
        )
        if exit_code != 0:
            return False, f"Ошибка копирования конфига: {err}"

        return True, "Конфигурация HAProxy сохранена"

    def reload(self):
        """Безопасная перезагрузка HAProxy"""
        check_systemd = "command -v systemctl >/dev/null && systemctl is-active haproxy >/dev/null"
        exit_code, _, _ = self._execute_ssh(check_systemd)

        if exit_code == 0:
            exit_code, out, err = self._execute_ssh("sudo systemctl reload haproxy")
            if exit_code == 0:
                return True, "HAProxy перезагружен через systemctl"

        pid_cmd = "cat /var/run/haproxy.pid 2>/dev/null || pidof haproxy || echo ''"
        _, pid, _ = self._execute_ssh(pid_cmd)
        pid = pid.strip().split()[0] if pid.strip() else ""

        if pid:
            reload_cmd = f"sudo haproxy -f {self.config_path} -p /var/run/haproxy.pid -sf {pid}"
        else:
            reload_cmd = f"sudo haproxy -f {self.config_path} -p /var/run/haproxy.pid"

        exit_code, out, err = self._execute_ssh(reload_cmd)
        if exit_code != 0:
            return False, f"Ошибка перезагрузки HAProxy: {err}"

        return True, "HAProxy перезагружен"

    # -------------------------------------------------------------------------
    # nginx stream (для AWG / UDP протоколов)
    # -------------------------------------------------------------------------

    def ensure_nginx_installed(self):
        """Устанавливает nginx со stream-модулем если не установлен / не хватает модуля"""
        # Проверяем наличие nginx
        exit_code, _, _ = self._execute_ssh("command -v nginx")
        if exit_code != 0:
            exit_code, out, err = self._execute_ssh(
                "sudo apt-get update -qq && sudo apt-get install -y nginx libnginx-mod-stream"
            )
            if exit_code != 0:
                return False, f"Ошибка установки nginx: {err}"
            self._execute_ssh("sudo systemctl enable nginx && sudo systemctl start nginx")
        else:
            # nginx уже есть — убедимся что stream-модуль установлен
            # libnginx-mod-stream создаёт /etc/nginx/modules-enabled/50-mod-stream.conf
            exit_code, _, _ = self._execute_ssh(
                "test -f /etc/nginx/modules-enabled/50-mod-stream.conf"
            )
            if exit_code != 0:
                exit_code, out, err = self._execute_ssh(
                    "sudo apt-get install -y libnginx-mod-stream"
                )
                if exit_code != 0:
                    return False, f"Ошибка установки libnginx-mod-stream: {err}"

        return True, "nginx со stream-модулем готов"

    def _ensure_nginx_stream_include(self):
        """
        Добавляет блок `stream { include /etc/nginx/stream.d/*.conf; }` в nginx.conf,
        если его там ещё нет. Работает через SFTP чтобы избежать проблем с heredoc.
        """
        # Создаём директорию stream.d
        self._execute_ssh("sudo mkdir -p /etc/nginx/stream.d")
        self._execute_ssh("sudo chown $USER:$USER /etc/nginx/stream.d")

        # Проверяем, уже ли есть блок stream
        exit_code, _, _ = self._execute_ssh(
            "grep -q 'stream.d' /etc/nginx/nginx.conf"
        )
        if exit_code == 0:
            return  # уже есть

        # Читаем текущий nginx.conf через SFTP
        try:
            pkey = parse_private_key(self.ssh_key, self.passphrase)
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(self.host, port=self.ssh_port, username=self.username, pkey=pkey, timeout=30)

            sftp = ssh_client.open_sftp()
            with sftp.file('/etc/nginx/nginx.conf', 'r') as f:
                current = f.read().decode('utf-8')

            stream_block = '\n\n# RootCloud: UDP stream proxy\nstream {\n    include /etc/nginx/stream.d/*.conf;\n}\n'
            new_content = current + stream_block

            temp_path = f"/tmp/nginx.conf.{int(time.time())}"
            with sftp.file(temp_path, 'w') as f:
                f.write(new_content)
            sftp.close()
            ssh_client.close()
        except Exception:
            return  # если не можем прочитать — пробуем через append как fallback
        else:
            self._execute_ssh(f"sudo cp {temp_path} /etc/nginx/nginx.conf && sudo rm {temp_path}")

    def update_nginx_stream_config(self, awg_backends):
        """
        Управляет iptables DNAT+MASQUERADE правилами для AWG (UDP) бэкендов.

        nginx stream НЕ используется для AWG: при Jc>0 nginx создаёт отдельную
        upstream-сессию для каждого junk-пакета, из-за чего handshake-ответы
        не доходят до клиента. iptables DNAT работает прозрачно на уровне ядра.

        При раздельных машинах (прокси ≠ AWG) без MASQUERADE AWG-сервер отвечает
        клиенту напрямую, минуя прокси — клиент дропает пакет (ждёт src прокси).
        MASQUERADE заменяет src на IP прокси → AWG отвечает прокси → conntrack
        восстанавливает оригинальный src для клиента.

        Для каждого бэкенда:
          PREROUTING udp --dport <listen_port> → DNAT <srv_ip>:<srv_port>
          POSTROUTING -d <srv_ip> --dport <srv_port> → MASQUERADE
        """
        if not awg_backends:
            return True, "Нет AWG бэкендов"

        # Включаем ip_forward (необходимо для forwarding между интерфейсами)
        self._execute_ssh("sudo sysctl -w net.ipv4.ip_forward=1")
        self._execute_ssh(
            "grep -q 'net.ipv4.ip_forward=1' /etc/sysctl.conf || "
            "echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf"
        )

        errors = []
        for backend in awg_backends:
            if not backend.servers_json:
                continue

            # Поддерживаем только один upstream (WireGuard — stateful, нельзя балансировать)
            srv = backend.servers_json[0]
            srv_ip = srv['ip']
            srv_port = srv['port']
            dst = f"{srv_ip}:{srv_port}"
            listen_port = backend.port

            # --- DNAT: входящий трафик на прокси-порт → AWG-сервер ---
            self._execute_ssh(
                f"sudo iptables -t nat -D PREROUTING -p udp --dport {listen_port} "
                f"-j DNAT --to-destination {dst} 2>/dev/null || true"
            )
            exit_code, _, err = self._execute_ssh(
                f"sudo iptables -t nat -I PREROUTING 1 -p udp --dport {listen_port} "
                f"-j DNAT --to-destination {dst}"
            )
            if exit_code != 0:
                errors.append(f"DNAT {listen_port}→{dst}: {err}")
                continue

            # --- MASQUERADE: заменяем src на IP прокси чтобы AWG отвечал обратно на прокси ---
            # Без этого при раздельных машинах AWG отвечает напрямую клиенту (асимметричный маршрут)
            self._execute_ssh(
                f"sudo iptables -t nat -D POSTROUTING -p udp -d {srv_ip} --dport {srv_port} "
                f"-j MASQUERADE 2>/dev/null || true"
            )
            exit_code, _, err = self._execute_ssh(
                f"sudo iptables -t nat -A POSTROUTING -p udp -d {srv_ip} --dport {srv_port} "
                f"-j MASQUERADE"
            )
            if exit_code != 0:
                errors.append(f"MASQUERADE →{dst}: {err}")

            # --- FORWARD: разрешаем форвардинг пакетов через прокси к AWG и обратно ---
            # После DNAT пакет идёт через FORWARD chain (не INPUT).
            # Если политика FORWARD=DROP — данные дропаются даже при успешном handshake.
            self._execute_ssh(
                f"sudo iptables -D FORWARD -p udp -d {srv_ip} --dport {srv_port} "
                f"-j ACCEPT 2>/dev/null || true"
            )
            self._execute_ssh(
                f"sudo iptables -I FORWARD 1 -p udp -d {srv_ip} --dport {srv_port} -j ACCEPT"
            )
            # Разрешаем ответные пакеты (ESTABLISHED/RELATED) через conntrack
            self._execute_ssh(
                "sudo iptables -C FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT "
                "2>/dev/null || sudo iptables -I FORWARD 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
            )

        if errors:
            return False, "; ".join(errors)
        return True, "iptables DNAT+MASQUERADE правила обновлены"

    # -------------------------------------------------------------------------
    # HAProxy backend / frontend конфиг (только TCP протоколы: xray, openvpn)
    # -------------------------------------------------------------------------

    def get_backends(self):
        """Получает список бэкендов из конфига HAProxy"""
        exit_code, config, err = self.get_config()
        if exit_code != 0:
            return []

        backends = []
        current_section = None

        for line in config.split('\n'):
            line = line.strip()
            if line.startswith('backend '):
                current_section = line[8:].strip()
                backends.append({'name': current_section, 'servers': []})
            elif current_section and line.startswith('server '):
                parts = line.split()
                if len(parts) >= 3:
                    backends[-1]['servers'].append({
                        'name': parts[1],
                        'address': parts[2]
                    })

        return backends

    def add_server_to_backend(self, backend_name, server_name, ip, port, options='check'):
        """Добавляет сервер в бэкенд через stats socket (динамически, без перезагрузки)"""
        cmd = f"add server {backend_name}/{server_name} {ip}:{port} {options}"
        exit_code, out, err = self._execute_socket_command(cmd)
        if exit_code == 0:
            self.enable_server(backend_name, server_name)
            return True, f"Сервер {server_name} добавлен"
        return False, err or out

    def remove_server_from_backend(self, backend_name, server_name):
        """Удаляет сервер из бэкенда"""
        cmd = f"del server {backend_name}/{server_name}"
        exit_code, out, err = self._execute_socket_command(cmd)
        return exit_code == 0, err or out

    def enable_server(self, backend_name, server_name):
        cmd = f"enable server {backend_name}/{server_name}"
        exit_code, out, err = self._execute_socket_command(cmd)
        return exit_code == 0, err or out

    def disable_server(self, backend_name, server_name):
        cmd = f"disable server {backend_name}/{server_name}"
        exit_code, out, err = self._execute_socket_command(cmd)
        return exit_code == 0, err or out

    def get_server_status(self, backend_name, server_name):
        cmd = f"show servers state {backend_name}"
        exit_code, out, err = self._execute_socket_command(cmd)
        if exit_code != 0:
            return None
        for line in out.split('\n'):
            if line.startswith(f'{backend_name},{server_name},'):
                parts = line.split(',')
                if len(parts) >= 10:
                    return {
                        'name': server_name,
                        'status': 'up' if parts[9] == '2' else 'down',
                        'weight': parts[7],
                        'addr': parts[4]
                    }
        return None

    def generate_backend_config(self, backend):
        """Генерирует HAProxy backend секцию (только TCP: xray, openvpn)"""
        config = f"""
backend {backend.name}
    mode {backend.mode}
    balance {backend.balance_algorithm}
"""
        for server in backend.servers_json:
            config += f"    server {server['name']} {server['ip']}:{server['port']} check\n"
        return config

    def generate_frontend_config(self, backend):
        """Генерирует HAProxy frontend секцию (только TCP: xray, openvpn)"""
        frontend_name = f"frontend_{backend.protocol_type}_{backend.id}"
        config = f"""
frontend {frontend_name}
    bind *:{backend.port}
    mode {backend.mode}
    default_backend {backend.name}
"""
        return config

    # -------------------------------------------------------------------------
    # XRay Reality (устанавливается на HAProxy для обхода DPI)
    # -------------------------------------------------------------------------

    def install_xray_reality_base(self):
        """Устанавливает XRay Reality Docker контейнер на HAProxy сервере и генерирует X25519 ключи.
        Возвращает (success, public_key, private_key).
        """
        # Установить Docker если отсутствует
        exit_code, _, _ = self._execute_ssh("command -v docker")
        if exit_code != 0:
            exit_code, out, err = self._execute_ssh(
                "curl -fsSL https://get.docker.com | sudo sh"
            )
            if exit_code != 0:
                return False, None, None

        # Создать рабочую директорию
        self._execute_ssh(
            "sudo mkdir -p /opt/xray-reality && sudo chown $USER:$USER /opt/xray-reality"
        )

        # Сгенерировать X25519 ключи через Docker
        exit_code, out, err = self._execute_ssh(
            "sudo docker run --rm ghcr.io/xtls/xray-core:latest xray x25519"
        )
        if exit_code != 0:
            return False, None, None

        private_match = re.search(r'Private key:\s*(\S+)', out)
        public_match = re.search(r'Public key:\s*(\S+)', out)
        if not private_match or not public_match:
            return False, None, None

        private_key = private_match.group(1)
        public_key = public_match.group(1)

        # Записать начальный пустой конфиг
        initial_config = json.dumps(
            {"inbounds": [], "outbounds": [{"tag": "direct", "protocol": "freedom"}],
             "routing": {"rules": []}},
            indent=2
        )
        ok, err = self._sftp_write(initial_config, '/opt/xray-reality/config.json')
        if not ok:
            return False, None, None

        # Записать docker-compose.yml
        compose_content = (
            "version: '3'\n"
            "services:\n"
            "  xray-reality:\n"
            "    image: ghcr.io/xtls/xray-core:latest\n"
            "    container_name: xray-reality\n"
            "    restart: unless-stopped\n"
            "    network_mode: host\n"
            "    volumes:\n"
            "      - ./config.json:/etc/xray/config.json\n"
            "    command: run -c /etc/xray/config.json\n"
        )
        ok, err = self._sftp_write(compose_content, '/opt/xray-reality/docker-compose.yml')
        if not ok:
            return False, None, None

        # Запустить контейнер
        exit_code, out, err = self._execute_ssh(
            "cd /opt/xray-reality && sudo docker compose up -d 2>&1 || "
            "cd /opt/xray-reality && sudo docker-compose up -d 2>&1"
        )
        if exit_code != 0:
            return False, None, None

        return True, public_key, private_key

    def update_xray_reality_config(self):
        """Генерирует и деплоит XRay Reality конфиг для всех Reality-групп этого HAProxy.
        Возвращает (success, message).
        """
        from app.models import ServerGroup, HaproxyBackend
        from app.utils.crypto import decrypt_data as _decrypt

        if not self.server.xray_private_key_encrypted:
            return False, "XRay Reality не установлен (нет приватного ключа)"

        private_key = _decrypt(self.server.xray_private_key_encrypted)

        groups = ServerGroup.query.filter_by(
            reality_enabled=True,
            reality_haproxy_server_id=self.server.id
        ).all()

        inbounds = []
        outbounds = []
        rules = []

        for group in groups:
            if not group.reality_port or not group.reality_relay_uuid:
                continue

            # Клиентские UUID для inbound
            client_entries = []
            for c in group.clients:
                if c.protocol_type == 'xray' and c.status == 'active' and c.extra_params:
                    uid = c.extra_params.get('uuid')
                    if uid:
                        client_entries.append({
                            'id': uid,
                            'email': c.email or f"{c.name}@example.com",
                            'flow': 'xtls-rprx-vision'
                        })

            # HAProxy XRay backend порт для этой группы на этом же сервере
            backend = HaproxyBackend.query.filter_by(
                protocol_type='xray',
                group_id=group.id,
                haproxy_server_id=self.server.id
            ).first()
            if not backend:
                continue

            sni = group.reality_sni or 'www.microsoft.com'
            in_tag = f"g{group.id}-in"
            out_tag = f"g{group.id}-out"

            inbounds.append({
                "tag": in_tag,
                "port": group.reality_port,
                "protocol": "vless",
                "settings": {
                    "clients": client_entries,
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": False,
                        "dest": f"{sni}:443",
                        "xver": 0,
                        "serverNames": [sni],
                        "privateKey": private_key,
                        "shortIds": [""]
                    }
                }
            })

            outbounds.append({
                "tag": out_tag,
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": backend.port,
                        "users": [{"id": group.reality_relay_uuid, "encryption": "none"}]
                    }]
                },
                "streamSettings": {"network": "tcp", "security": "none"}
            })

            rules.append({
                "type": "field",
                "inboundTag": [in_tag],
                "outboundTag": out_tag
            })

        # Дефолтный freedom outbound (fallback)
        outbounds.append({"tag": "direct", "protocol": "freedom"})

        config = {
            "inbounds": inbounds,
            "outbounds": outbounds,
            "routing": {"domainStrategy": "AsIs", "rules": rules}
        }

        config_json = json.dumps(config, indent=2, ensure_ascii=False)
        ok, err = self._sftp_write(config_json, '/opt/xray-reality/config.json')
        if not ok:
            return False, f"Ошибка записи конфига: {err}"

        # Перезагрузить XRay Reality
        self._execute_ssh(
            "sudo docker exec xray-reality kill -HUP 1 2>/dev/null || "
            "sudo docker restart xray-reality 2>/dev/null || true"
        )
        return True, "XRay Reality конфиг обновлён"

    def ensure_haproxy_installed(self):
        """Проверяет, установлен ли HAProxy, и устанавливает при необходимости"""
        exit_code, out, err = self._execute_ssh("command -v haproxy")
        if exit_code == 0:
            return True, "HAProxy already installed"

        install_cmd = "sudo apt-get update && sudo apt-get install -y haproxy"
        exit_code, out, err = self._execute_ssh(install_cmd)
        if exit_code != 0:
            return False, f"Installation failed: {err}"

        self._execute_ssh("sudo systemctl enable haproxy && sudo systemctl start haproxy")
        return True, "HAProxy installed successfully"
