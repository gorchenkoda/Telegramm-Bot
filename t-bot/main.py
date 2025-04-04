import asyncio
import logging
from telegram.ext import Application
from core.exceptions import setup_exception_handlers
from handlers import setup_handlers
from jobs import setup_jobs
from config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

async def startup(app: Application):
    """Инициализация при запуске"""
    setup_exception_handlers(app)
    setup_handlers(app)
    await setup_jobs(app)
    logging.info("Bot started")

async def shutdown(app: Application):
    """Корректное завершение"""
    await app.job_queue.stop()
    await app.updater.stop()
    await app.stop()
    logging.info("Bot stopped")

def main():
    app = Application.builder() \
        .token(settings.TOKEN) \
        .post_init(startup) \
        .post_shutdown(shutdown) \
        .build()

    try:
        app.run_polling()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        logging.critical(f"Bot crashed: {e}")

if __name__ == "__main__":
    main()