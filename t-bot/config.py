import os
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent


class Settings:
    # Telegram
    TOKEN: str = os.getenv("BOT_TOKEN")
    ADMIN_IDS: list[int] = [int(x) for x in os.getenv("ADMIN_IDS", "").split(",") if x]

    # Database
    DB_URL: str = os.getenv("DB_URL", f"sqlite+aiosqlite:///{BASE_DIR}/database.db")
    DB_ECHO: bool = os.getenv("DB_ECHO", "false").lower() == "true"

    # Payments
    YOOMONEY_TOKEN: str = os.getenv("YOOMONEY_TOKEN")
    YOOMONEY_RECEIVER: str = os.getenv("YOOMONEY_RECEIVER")
    PAYMENT_TIMEOUT: int = int(os.getenv("PAYMENT_TIMEOUT", "3600"))

    # VPN
    VPN_SERVER_IP: str = os.getenv("VPN_SERVER_IP")
    SSH_USER: str = os.getenv("SSH_USER")
    SSH_KEY_PATH: str = os.getenv("SSH_KEY_PATH")
    SSH_TIMEOUT: int = int(os.getenv("SSH_TIMEOUT", "30"))
    SSH_RETRIES: int = int(os.getenv("SSH_RETRIES", "3"))
    VPN_CONFIGS_DIR: str = os.getenv("VPN_CONFIGS_DIR", str(BASE_DIR / "files/vpn_configs"))

    # Prices
    PRICES: dict = {
        '1month': int(os.getenv("PRICE_1MONTH", "250")),
        '3months': int(os.getenv("PRICE_3MONTHS", "600")),
        '6months': int(os.getenv("PRICE_6MONTHS", "1000")),
        '1year': int(os.getenv("PRICE_1YEAR", "1800"))
    }

    EXPIRATION_DAYS: dict = {
        '1month': 30,
        '3months': 90,
        '6months': 180,
        '1year': 365
    }


settings = Settings()