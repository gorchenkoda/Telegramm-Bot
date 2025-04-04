import paramiko
import socket
import time
from typing import Tuple, Optional
from config import settings
import logging

logger = logging.getLogger(__name__)


class SSHManager:
    def __init__(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def execute_command(self, command: str) -> Tuple[Optional[str], Optional[str]]:
        for attempt in range(settings.SSH_RETRIES):
            try:
                self.ssh.connect(
                    settings.VPN_SERVER_IP,
                    username=settings.SSH_USER,
                    key_filename=settings.SSH_KEY_PATH,
                    timeout=settings.SSH_TIMEOUT
                )

                stdin, stdout, stderr = self.ssh.exec_command(command)
                output = stdout.read().decode().strip()
                error = stderr.read().decode().strip()

                self.ssh.close()

                if error:
                    raise Exception(f"SSH error: {error}")
                return output, None

            except (socket.timeout, paramiko.SSHException) as e:
                if attempt == settings.SSH_RETRIES - 1:
                    return None, str(e)
                time.sleep(1)

        return None, "Max retries reached"


ssh_manager = SSHManager()