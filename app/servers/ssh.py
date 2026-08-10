import paramiko
from paramiko import SSHClient, AutoAddPolicy, RSAKey, DSSKey, ECDSAKey, Ed25519Key
import io

# Таймауты SSH. Важно: `timeout` у connect() ограничивает только TCP-соединение.
# Если сервер принял соединение и замолчал (обрыв канала, перегрузка, потеря
# маршрута), чтение из канала блокируется навсегда. Эти операции вызываются в том
# числе прямо из веб-запросов, поэтому каждый зависший вызов навсегда занимает
# поток gunicorn — так панель и переставала отвечать.
CONNECT_TIMEOUT = 10
BANNER_TIMEOUT = 15
AUTH_TIMEOUT = 15
COMMAND_TIMEOUT = 60


def _connect(ip, port, username, key):
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(
        hostname=ip,
        port=port,
        username=username,
        pkey=key,
        timeout=CONNECT_TIMEOUT,
        banner_timeout=BANNER_TIMEOUT,
        auth_timeout=AUTH_TIMEOUT,
        allow_agent=False,
        look_for_keys=False
    )
    # Обрывает соединение, если удалённая сторона перестала отвечать
    transport = client.get_transport()
    if transport is not None:
        transport.set_keepalive(15)
    return client


def test_ssh_connection(ip, port, username, private_key_str, passphrase=None):
    """
    Проверяет SSH-подключение и возвращает (success, error_message)
    """
    client = None
    try:
        # Подготовка ключа
        key = parse_private_key(private_key_str, passphrase)
        client = _connect(ip, port, username, key)
        return True, None
    except Exception as e:
        return False, str(e)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

def parse_private_key(key_str, passphrase=None):
    """
    Парсит строку приватного ключа в объект PKey.
    Поддерживает RSA, DSA, ECDSA, Ed25519.
    """
    key_str = key_str.strip()
    key_file = io.StringIO(key_str)
    passphrase_bytes = passphrase.encode() if passphrase else None

    # Попробуем разные форматы
    for key_class in [RSAKey, DSSKey, ECDSAKey, Ed25519Key]:
        try:
            key_file.seek(0)
            return key_class.from_private_key(key_file, password=passphrase_bytes)
        except paramiko.ssh_exception.SSHException:
            continue
        except Exception:
            continue
    raise ValueError("Не удалось распознать формат приватного ключа")

def execute_ssh_command(ip, port, username, private_key_str, command, passphrase=None):
    """
    Выполняет команду на удаленном сервере и возвращает stdout, stderr.
    """
    client = None
    try:
        key = parse_private_key(private_key_str, passphrase)
        client = _connect(ip, port, username, key)
        stdin, stdout, stderr = client.exec_command(command, timeout=COMMAND_TIMEOUT)
        # timeout выше ставится на канал, поэтому чтение и recv_exit_status()
        # не могут заблокироваться навсегда — при простое бросается socket.timeout
        output = stdout.read().decode()
        error = stderr.read().decode()
        exit_status = stdout.channel.recv_exit_status()
        return exit_status, output, error
    except Exception as e:
        return -1, '', str(e)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass