import os
import time
from datetime import datetime, timedelta
from typing import Optional
from core.ssh_client import ssh_manager
from config import settings
from database.crud import CRUD
from database.models import VPNConfig
import logging

logger = logging.getLogger(__name__)


class VPNService:
    @staticmethod
    async def generate_config(username: str, period: str) -> Optional[str]:
        """Генерация конфига OpenVPN с улучшенной обработкой ошибок"""
        try:
            # 1. Проверка имени пользователя
            if not all(c.isalnum() or c in '_-' for c in username) or len(username) > 32:
                raise ValueError("Invalid username format")

            # 2. Подготовка сервера
            commands = [
                f"sudo rm -f /tmp/{username}*",
                f"cd /etc/openvpn/easy-rsa/ && sudo ./easyrsa --batch build-client-full {username} nopass",
                f"sudo cp /etc/openvpn/easy-rsa/pki/issued/{username}.crt /tmp/",
                f"sudo cp /etc/openvpn/easy-rsa/pki/private/{username}.key /tmp/",
                f"sudo cp /etc/openvpn/easy-rsa/pki/ca.crt /tmp/",
                f"sudo chown {settings.SSH_USER}:{settings.SSH_USER} /tmp/{username}.* /tmp/ca.crt"
            ]

            for cmd in commands:
                output, error = ssh_manager.execute_command(cmd)
                if error:
                    raise Exception(f"Command failed: {cmd}. Error: {error}")

            # 3. Получение сертификатов
            certs = {}
            for cert_type in ['ca.crt', f'{username}.crt', f'{username}.key']:
                content, error = ssh_manager.execute_command(f"cat /tmp/{cert_type}")
                if error:
                    raise Exception(f"Failed to read {cert_type}")
                certs[cert_type.split('.')[0]] = content

            # 4. Создание конфига
            config_content = f"""client
dev tun
proto udp
remote {settings.VPN_SERVER_IP} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-CBC
verb 3

<ca>
{certs['ca']}
</ca>
<cert>
{certs[username]}
</cert>
<key>
{certs[username]}
</key>
"""
            # 5. Сохранение файла
            os.makedirs(settings.VPN_CONFIGS_DIR, exist_ok=True)
            config_file = f"VPN_{username}_{period}.ovpn"
            config_path = os.path.join(settings.VPN_CONFIGS_DIR, config_file)

            with open(config_path, 'w') as f:
                f.write(config_content)

            os.chmod(config_path, 0o600)
            return config_file

        except Exception as e:
            logger.error(f"VPN config generation failed: {str(e)}")
            raise

    @staticmethod
    async def revoke_config(username: str) -> bool:
        """Отзыв VPN конфига"""
        cmd = f"cd /etc/openvpn/easy-rsa/ && sudo ./easyrsa revoke {username} && sudo ./easyrsa gen-crl"
        output, error = ssh_manager.execute_command(cmd)
        return error is None