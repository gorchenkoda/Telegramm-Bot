from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes
from services.vpn_service import VPNService
from config import settings
from database.crud import CRUD
import logging

logger = logging.getLogger(__name__)


async def handle_vpn_config_request(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обработчик запроса VPN конфига"""
    user = update.effective_user
    try:
        # Проверка существующих конфигов
        existing_configs = await CRUD.get_user_configs(user.id)
        if len(existing_configs) >= 3:
            await update.message.reply_text("❌ У вас уже есть 3 активных конфига")
            return

        # Создание платежа и конфига
        period = context.args[0] if context.args else '1month'
        config_file = await VPNService.generate_config(f"user_{user.id}", period)

        # Сохранение в БД
        expiry_date = datetime.now() + timedelta(days=settings.EXPIRATION_DAYS[period])
        await CRUD.create_config(user.id, config_file, expiry_date)

        # Отправка файла
        config_path = os.path.join(settings.VPN_CONFIGS_DIR, config_file)
        with open(config_path, 'rb') as f:
            await update.message.reply_document(
                document=f,
                caption=f"Ваш VPN конфиг ({period})"
            )

    except Exception as e:
        logger.error(f"Config request failed: {str(e)}")
        await update.message.reply_text("❌ Ошибка при создании конфига")