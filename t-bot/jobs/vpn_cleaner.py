from datetime import datetime
import os
from config import settings
from services.vpn_service import VPNService
from database.crud import CRUD
import logging

logger = logging.getLogger(__name__)


async def cleanup_expired_configs(context: ContextTypes.DEFAULT_TYPE):
    """Очистка просроченных конфигов"""
    try:
        expired_configs = await CRUD.get_expired_configs()
        for config in expired_configs:
            try:
                # Отзыв на сервере
                username = config.file_name.split('_')[1]
                if await VPNService.revoke_config(username):
                    # Удаление файла
                    config_path = os.path.join(settings.VPN_CONFIGS_DIR, config.file_name)
                    if os.path.exists(config_path):
                        os.remove(config_path)

                    # Удаление из БД
                    await CRUD.delete_config(config.id)
                    logger.info(f"Удален конфиг: {config.file_name}")
            except Exception as e:
                logger.error(f"Ошибка удаления конфига {config.file_name}: {str(e)}")

    except Exception as e:
        logger.error(f"Ошибка в cleanup_expired_configs: {str(e)}")