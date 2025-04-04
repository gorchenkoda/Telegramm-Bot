import logging
from telegram.ext import Application
from handlers import setup_handlers
from jobs import setup_jobs
from config import settings
from core.exceptions import setup_exception_handlers
import asyncio

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)


async def startup(app: Application):
    """Инициализация при запуске"""
    setup_exception_handlers(app)
    setup_handlers(app)
    await setup_jobs(app)
    logging.info("Bot started")


async def shutdown(app: Application):
    """Корректное завершение работы"""
    await app.job_queue.stop()
    await app.updater.stop()
    await app.stop()
    logging.info("Bot stopped")


def main():
    app = Application.builder().token(settings.TOKEN).build()

    # Настройка обработчиков
    from handlers.common import start, help
    from handlers.vpn import configs
    from handlers.admin import server

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help))
    app.add_handler(CommandHandler("vpn", configs.handle_vpn_config_request))
    app.add_handler(CommandHandler("server", server.handle_server_status))

    # Планировщик задач
    job_queue = app.job_queue
    job_queue.run_daily(
        cleanup_expired_configs,
        time=datetime.time(3, 0)  # Ежедневно в 3:00
    )

    try:
        app.run_polling()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.critical(f"Bot crashed: {e}")
    finally:
        asyncio.run(shutdown(app))


if __name__ == "__main__":
    main()