"""
Модуль для установки VPN-протоколов через Docker
"""


def install_docker_if_needed(server):
    """
    Возвращает команды для установки Docker, если он не установлен
    """
    script = """# Установка Docker
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com -o get-docker.sh
  sudo sh get-docker.sh
  sudo systemctl enable docker
  sudo systemctl start docker
fi

# Установка Docker Compose
if ! command -v docker-compose >/dev/null 2>&1; then
  # Определяем архитектуру системы
  ARCH=$(uname -s)-$(uname -m)
  sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$ARCH" -o /usr/local/bin/docker-compose
  sudo chmod +x /usr/local/bin/docker-compose
    fi"""
    return script


def install_amnezia_wg(port, custom_params=None):
    """
    Генерирует команды для нативной установки AmneziaWG через ядерный модуль.
    Не использует Docker — amneziawg-go (userspace) имеет баг с TUN-записью.
    """
    jc   = custom_params.get('jc',   5)        if custom_params else 5
    jmin = custom_params.get('jmin', 30)       if custom_params else 30
    jmax = custom_params.get('jmax', 50)       if custom_params else 50
    s1   = custom_params.get('s1',   220)      if custom_params else 220
    s2   = custom_params.get('s2',   230)      if custom_params else 230
    h1   = custom_params.get('h1',   1855549004) if custom_params else 1855549004
    h2   = custom_params.get('h2',   2882373428) if custom_params else 2882373428
    h3   = custom_params.get('h3',   3625691520) if custom_params else 3625691520
    h4   = custom_params.get('h4',   3868285620) if custom_params else 3868285620
    mtu  = custom_params.get('mtu',  1420)     if custom_params else 1420

    key_override = ""
    if custom_params and 'private_key' in custom_params:
        priv = custom_params['private_key']
        pub  = custom_params['server_public_key']
        key_override = f"""echo "{priv}" | sudo tee /opt/amnezia/awg/conf/privatekey > /dev/null
echo "{pub}" | sudo tee /opt/amnezia/awg/conf/server_public_key > /dev/null"""

    script = f"""# Установка AmneziaWG (нативный режим, ядерный модуль)
sudo add-apt-repository ppa:amnezia/ppa -y
sudo apt-get update -q
sudo apt-get install -y amneziawg

sudo mkdir -p /opt/amnezia/awg/conf
sudo chmod 700 /opt/amnezia/awg/conf

{key_override}

# Генерируем ключи, если их нет
if [ ! -f /opt/amnezia/awg/conf/privatekey ]; then
    awg genkey | sudo tee /opt/amnezia/awg/conf/privatekey > /dev/null
    sudo cat /opt/amnezia/awg/conf/privatekey | awg pubkey | sudo tee /opt/amnezia/awg/conf/server_public_key > /dev/null
fi

PRIVATE_KEY=$(sudo cat /opt/amnezia/awg/conf/privatekey)
SERVER_PUBLIC_KEY=$(sudo cat /opt/amnezia/awg/conf/server_public_key)

# Создаём конфиг
sudo tee /opt/amnezia/awg/conf/wg0.conf > /dev/null << WGEOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = 10.8.0.1/24
ListenPort = {port}
Table = off
Jc = {jc}
Jmin = {jmin}
Jmax = {jmax}
S1 = {s1}
S2 = {s2}
H1 = {h1}
H2 = {h2}
H3 = {h3}
H4 = {h4}
MTU = {mtu}
WGEOF
sudo chmod 600 /opt/amnezia/awg/conf/wg0.conf

# Загружаем ядерный модуль и поднимаем интерфейс
sudo modprobe amneziawg
sudo awg-quick down /opt/amnezia/awg/conf/wg0.conf 2>/dev/null || true
sudo awg-quick up /opt/amnezia/awg/conf/wg0.conf

# Включаем форвардинг и NAT
sudo sysctl -w net.ipv4.ip_forward=1
grep -qxF 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
IFACE=$(ip route | grep default | awk '{{print $5}}' | head -1)
sudo iptables -C FORWARD -i wg0 -j ACCEPT 2>/dev/null || sudo iptables -A FORWARD -i wg0 -j ACCEPT
sudo iptables -C FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || sudo iptables -A FORWARD -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o $IFACE -j MASQUERADE 2>/dev/null || sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $IFACE -j MASQUERADE

# Автозапуск через systemd
sudo mkdir -p /etc/amneziawg
sudo ln -sf /opt/amnezia/awg/conf/wg0.conf /etc/amneziawg/wg0.conf
sudo systemctl enable awg-quick@wg0 2>/dev/null || true

# Сохраняем параметры для панели
sudo tee /opt/amnezia/awg/conf/params.json > /dev/null << PARAMS_EOF
{{
  "server_public_key": "$SERVER_PUBLIC_KEY",
  "private_key": "$PRIVATE_KEY",
  "jc": {jc}, "jmin": {jmin}, "jmax": {jmax},
  "s1": {s1}, "s2": {s2},
  "h1": {h1}, "h2": {h2}, "h3": {h3}, "h4": {h4},
  "mtu": {mtu}
}}
PARAMS_EOF

echo "AWG_PARAMS_JSON:$(sudo cat /opt/amnezia/awg/conf/params.json)"
"""
    return script


def install_xray_reality(port, custom_params=None):
    """
    Генерирует команды для установки XRay Reality.
    Если переданы custom_params, использует их приватный ключ.
    """
    if custom_params and 'private_key' in custom_params:
        priv_key = custom_params['private_key']
        pub_key = custom_params['public_key']
    else:
        # Генерируем новые, если нет переданных
        # Мы не можем легко запустить docker run здесь для генерации и потом использовать в том же скрипте
        # без лишних сложностей, поэтому просто используем заглушки или генерируем на стороне python (лучше)
        priv_key = "$PRIVATE_KEY" # будет вычислено в bash ниже
        pub_key = "$PUBLIC_KEY"

    key_gen_logic = ""
    if not custom_params:
        key_gen_logic = """
KEY_OUTPUT=$(sudo docker run --rm teddysun/xray:latest xray x25519)
PRIVATE_KEY=$(echo "$KEY_OUTPUT" | grep "PrivateKey:" | awk '{print $2}')
PUBLIC_KEY=$(echo "$KEY_OUTPUT" | grep "PublicKey:" | awk '{print $2}')
"""
    else:
        key_gen_logic = f"""
PRIVATE_KEY="{priv_key}"
PUBLIC_KEY="{pub_key}"
"""

    script = f'''# Установка XRay Reality
sudo mkdir -p /opt/amnezia/xray
sudo chown -R $USER:$USER /opt/amnezia/xray

{key_gen_logic}

# Создание конфига XRay
cat > /opt/amnezia/xray/config.json << EOF
{{
  "log": {{ "loglevel": "warning" }},
  "stats": {{}},
  "api": {{ "tag": "api", "services": ["StatsService"] }},
  "policy": {{
    "levels": {{ "0": {{ "statsUserUplink": true, "statsUserDownlink": true }} }},
    "system": {{ "statsInboundUplink": true, "statsInboundDownlink": true }}
  }},
  "inbounds": [
    {{
      "port": {port},
      "protocol": "vless",
      "settings": {{ "clients": [], "decryption": "none" }},
      "streamSettings": {{
        "network": "tcp",
        "security": "reality",
        "realitySettings": {{
          "dest": "www.microsoft.com:443",
          "serverNames": ["www.microsoft.com", "www.bing.com"],
          "privateKey": "$PRIVATE_KEY",
          "shortIds": ["6ba85179e30d4fc2"]
        }}
      }}
    }},
    {{
      "listen": "127.0.0.1", "port": 10085, "protocol": "dokodemo-door",
      "settings": {{ "address": "127.0.0.1" }}, "tag": "api"
    }}
  ],
  "outbounds": [ {{ "protocol": "freedom", "tag": "direct" }} ],
  "routing": {{ "rules": [ {{ "type": "field", "inboundTag": ["api"], "outboundTag": "api" }} ] }}
}}
EOF

cat > /opt/amnezia/xray/docker-compose.yml << 'EOF'
version: '3.8'
services:
  xray:
    image: teddysun/xray:latest
    container_name: xray-reality
    environment: [TZ=UTC]
    volumes: [./config.json:/etc/xray/config.json]
    ports: ["{port}:{port}"]
    restart: unless-stopped
EOF

cd /opt/amnezia/xray
sudo docker-compose up -d
echo "XRAY_KEYS_JSON:{{\"private_key\": \"$PRIVATE_KEY\", \"public_key\": \"$PUBLIC_KEY\"}}"
'''
    return script


def install_openvpn_cloak(port):
    """
    Установка OpenVPN over Cloak через Docker
    """
    script = f"""# Установка OpenVPN over Cloak
mkdir -p /opt/amnezia/openvpn

# Создание docker-compose.yml
cat > /opt/amnezia/openvpn/docker-compose.yml << 'EOF'
version: '3.8'

services:
  openvpn:
    image: kylemanna/openvpn:latest
    container_name: openvpn
    cap_add:
      - NET_ADMIN
    volumes:
      - ./ovpn-data:/etc/openvpn
    ports:
      - "1194:1194/udp"
    restart: unless-stopped

  cloak:
    image: cbeuw/cloak:latest
    container_name: cloak
    network_mode: host
    volumes:
      - ./cloak-config:/root/.cloak
    environment:
      - CK_PORT={port}
      - CK_REDIRECT=127.0.0.1:1194
      - CK_PROXYBOOK=shadowsocks
    restart: unless-stopped
EOF

# Инициализация OpenVPN
cd /opt/amnezia/openvpn
SERVER_IP=$(curl -s ifconfig.me)
docker-compose run --rm openvpn ovpn_genconfig -u udp://$SERVER_IP
docker-compose run --rm openvpn ovpn_initpki

# Запуск сервисов
docker-compose up -d
    """
    return script


def get_protocol_status(protocol_type):
    """
    Возвращает команду для проверки статуса протокола.
    AWG работает нативно (ядерный модуль), остальные — через Docker.
    """
    if protocol_type == 'awg':
        return "sudo awg show wg0 2>/dev/null && echo 'running' || echo 'stopped'"

    container_names = {
        'xray': 'xray-reality',
        'openvpn': 'openvpn'
    }
    container = container_names.get(protocol_type)
    if not container:
        return None

    return f"sudo docker ps --filter name={container} --format '{{{{.Status}}}}'"