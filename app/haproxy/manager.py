import paramiko
import time
from io import StringIO
from app.utils.crypto import decrypt_data

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
            key_file = StringIO(self.ssh_key)
            if self.passphrase:
                pkey = paramiko.RSAKey.from_private_key(key_file, password=self.passphrase)
            else:
                pkey = paramiko.RSAKey.from_private_key(key_file)

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
            key_file = StringIO(self.ssh_key)
            if self.passphrase:
                pkey = paramiko.RSAKey.from_private_key(key_file, password=self.passphrase)
            else:
                pkey = paramiko.RSAKey.from_private_key(key_file)

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
            key_file = StringIO(self.ssh_key)
            pkey = (
                paramiko.RSAKey.from_private_key(key_file, password=self.passphrase)
                if self.passphrase
                else paramiko.RSAKey.from_private_key(key_file)
            )
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
        Управляет iptables DNAT-правилами для AWG (UDP) бэкендов.

        nginx stream НЕ используется для AWG: при Jc>0 nginx создаёт отдельную
        upstream-сессию для каждого junk-пакета, из-за чего handshake-ответы
        не доходят до клиента. iptables DNAT работает прозрачно на уровне ядра.

        Для каждого бэкенда с одним upstream-сервером добавляем DNAT-правило:
          PREROUTING udp --dport <backend.port> → <srv_ip>:<srv_port>
        """
        if not awg_backends:
            return True, "Нет AWG бэкендов"

        errors = []
        for backend in awg_backends:
            if not backend.servers_json:
                continue

            # Поддерживаем только один upstream (WireGuard — stateful, нельзя балансировать)
            srv = backend.servers_json[0]
            dst = f"{srv['ip']}:{srv['port']}"
            listen_port = backend.port

            # Удаляем старое правило если есть, добавляем новое
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

        if errors:
            return False, "; ".join(errors)
        return True, "iptables DNAT правила обновлены"

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
