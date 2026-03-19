import paramiko
from paramiko import SSHClient, AutoAddPolicy, RSAKey, DSSKey, ECDSAKey, Ed25519Key
import io

def test_ssh_connection(ip, port, username, private_key_str, passphrase=None):
    """
    Проверяет SSH-подключение и возвращает (success, error_message)
    """
    try:
        # Подготовка ключа
        key = parse_private_key(private_key_str, passphrase)
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(
            hostname=ip,
            port=port,
            username=username,
            pkey=key,
            timeout=10,
            allow_agent=False,
            look_for_keys=False
        )
        client.close()
        return True, None
    except Exception as e:
        return False, str(e)

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
    try:
        key = parse_private_key(private_key_str, passphrase)
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(
            hostname=ip,
            port=port,
            username=username,
            pkey=key,
            timeout=10,
            allow_agent=False,
            look_for_keys=False
        )
        stdin, stdout, stderr = client.exec_command(command)
        exit_status = stdout.channel.recv_exit_status()
        output = stdout.read().decode()
        error = stderr.read().decode()
        client.close()
        return exit_status, output, error
    except Exception as e:
        return -1, '', str(e)