import os
from pathlib import Path
from dotenv import load_dotenv
from typing import List

load_dotenv()

BASE_DIR = Path(__file__).parent


class Settings:
    # Telegram
    TOKEN: str = os.getenv("BOT_TOKEN")
    ADMIN_IDS: List[int] = [int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x]

    # Database
    DB_URL: str = os.getenv("DB_URL", f"sqlite+aiosqlite:///{BASE_DIR}/database.db")
    DB_ECHO: bool = os.getenv("DB_ECHO", "false").lower() == "true"

    # Payments
    PAYMENT_TOKEN: str = os.getenv("PAYMENT_TOKEN")

    @property
    def database_config(self):
        return {
            "url": self.DB_URL,
            "echo": self.DB_ECHO,
            "connect_args": {"check_same_thread": False}
        }


settings = Settings()